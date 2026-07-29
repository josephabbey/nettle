package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/josephabbey/nettle/bus"
	"github.com/josephabbey/nettle/config"
	"github.com/josephabbey/nettle/domain"
)

type WebService struct {
	cfg *config.Config
	bus bus.Bus
	log *slog.Logger

	mu          sync.Mutex
	started     bool
	ctx         context.Context
	cancel      context.CancelFunc
	server      *http.Server
	listener    net.Listener
	unsubscribe func()

	store *webStore
	feed  *webFeed
}

type webStore struct {
	mu          sync.RWMutex
	leases      map[string]leaseView
	dnsRecords  map[string]dnsRecordView
	staticHosts []staticHostView
	updatedAt   time.Time
	tld         string
}

type webFeed struct {
	mu        sync.Mutex
	nextID    uint64
	listeners map[uint64]chan webEvent
}

type webEvent struct {
	Type string `json:"type"`
	Data any    `json:"data"`
}

type webState struct {
	GeneratedAt time.Time        `json:"generatedAt"`
	Counts      webCounts        `json:"counts"`
	Leases      []leaseView      `json:"leases"`
	DNSRecords  []dnsRecordView  `json:"dnsRecords"`
	StaticHosts []staticHostView `json:"staticHosts"`
}

type webCounts struct {
	Leases      int `json:"leases"`
	DNSRecords  int `json:"dnsRecords"`
	StaticHosts int `json:"staticHosts"`
}

type staticHostView struct {
	Hostname     string `json:"hostname"`
	HardwareAddr string `json:"hardwareAddr"`
	Address      string `json:"address"`
}

type leaseView struct {
	Key          string    `json:"key"`
	Hostname     string    `json:"hostname"`
	HardwareAddr string    `json:"hardwareAddr"`
	Address      string    `json:"address"`
	Interface    string    `json:"interface"`
	LeaseUntil   time.Time `json:"leaseUntil"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

type dnsRecordView struct {
	Name      string    `json:"name"`
	Address   string    `json:"address"`
	CNAME     string    `json:"cname"`
	Type      string    `json:"type"`
	UpdatedAt time.Time `json:"updatedAt"`
}

func NewWeb(cfg *config.Config, b bus.Bus, logger *slog.Logger) *WebService {
	if logger == nil {
		logger = slog.Default()
	}
	return &WebService{
		cfg:   cfg,
		bus:   b,
		log:   logger.With("component", "web"),
		store: newWebStore(cfg, cfg.Global.TLD),
		feed:  newWebFeed(),
	}
}

func (s *WebService) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return nil
	}

	addr := strings.TrimSpace(s.cfg.Web.Addr)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	s.started = true
	s.ctx, s.cancel = context.WithCancel(ctx)
	s.listener = ln
	s.server = &http.Server{
		Handler: s.routes(),
	}

	if s.bus != nil {
		events, unsubscribe := s.bus.Subscribe(64)
		s.unsubscribe = unsubscribe
		go s.consumeEvents(events)
	}

	go func() {
		<-s.ctx.Done()
		_ = s.Stop(context.Background())
	}()

	go func() {
		if err := s.server.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.log.Error("web server stopped", "error", err)
		}
	}()

	s.log.Info("web service started", "addr", ln.Addr().String())
	return nil
}

func (s *WebService) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.started {
		s.mu.Unlock()
		return nil
	}
	s.started = false
	cancel := s.cancel
	s.cancel = nil
	unsubscribe := s.unsubscribe
	s.unsubscribe = nil
	server := s.server
	s.server = nil
	listener := s.listener
	s.listener = nil
	s.mu.Unlock()

	if unsubscribe != nil {
		unsubscribe()
	}
	if cancel != nil {
		cancel()
	}
	if listener != nil {
		_ = listener.Close()
	}
	var err error
	if server != nil {
		err = server.Shutdown(ctx)
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
	}
	if err == nil {
		s.log.Info("web service stopped")
	}
	return err
}

func (s *WebService) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

func (s *WebService) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.serveIndex)
	mux.Handle("/assets/", http.StripPrefix("/assets/", http.FileServer(http.FS(webAssetFS))))
	mux.HandleFunc("/healthz", s.serveHealth)
	mux.HandleFunc("/api/state", s.serveState)
	mux.HandleFunc("/api/leases", s.serveLeases)
	mux.HandleFunc("/api/dns-records", s.serveDNSRecords)
	mux.HandleFunc("/api/static-hosts", s.serveStaticHosts)
	mux.HandleFunc("/events", s.serveEvents)
	return mux
}

func (s *WebService) serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(webIndexHTML)
}

func (s *WebService) serveHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *WebService) serveState(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.snapshot())
}

func (s *WebService) serveLeases(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.snapshot().Leases)
}

func (s *WebService) serveDNSRecords(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.snapshot().DNSRecords)
}

func (s *WebService) serveStaticHosts(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.store.snapshot().StaticHosts)
}

func (s *WebService) serveEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	events, unsubscribe := s.feed.subscribe()
	defer unsubscribe()

	if err := writeSSE(w, "snapshot", s.store.snapshot()); err != nil {
		return
	}
	flusher.Flush()

	keepAlive := time.NewTicker(25 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepAlive.C:
			if _, err := fmt.Fprint(w, ": ping\n\n"); err != nil {
				return
			}
			flusher.Flush()
		case event, ok := <-events:
			if !ok {
				return
			}
			if err := writeSSE(w, event.Type, event.Data); err != nil {
				return
			}
			flusher.Flush()
		}
	}
}

func (s *WebService) consumeEvents(events <-chan bus.Event) {
	for {
		select {
		case <-s.ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			switch ev := event.(type) {
			case domain.DNSRecordUpserted:
				view := s.store.upsertDNS(ev.Record)
				if view.Name != "" {
					s.feed.publish(webEvent{Type: "dns", Data: view})
				}
			case domain.StaticHostUpserted:
				view := s.store.upsertStaticHost(ev.StaticHost)
				s.feed.publish(webEvent{Type: "static", Data: view})
			case domain.DHCPLeaseAssigned:
				leaseView := s.store.upsertLease(ev.Lease)
				s.feed.publish(webEvent{Type: "lease", Data: leaseView})
				if hostname := strings.TrimSpace(ev.Lease.Hostname); hostname != "" {
					addr := ev.Lease.Address
					dnsView := s.store.upsertDNS(domain.DNSRecord{
						Name: domain.EnsureTLD(hostname, s.store.tld),
						Addr: &addr,
					})
					if dnsView.Name != "" {
						s.feed.publish(webEvent{Type: "dns", Data: dnsView})
					}
				}
			}
		}
	}
}

func newWebStore(cfg *config.Config, tld string) *webStore {
	store := &webStore{
		leases:      map[string]leaseView{},
		dnsRecords:  map[string]dnsRecordView{},
		staticHosts: []staticHostView{},
		tld:         tld,
	}
	for _, sh := range cfg.StaticHosts {
		store.staticHosts = append(store.staticHosts, staticHostView{
			Hostname:     domain.EnsureTLD(strings.TrimSpace(sh.Hostname), tld),
			HardwareAddr: strings.TrimSpace(sh.HardwareAddr),
			Address:      sh.Address.String(),
		})
	}
	for _, host := range cfg.Hosts {
		record := domain.DNSRecord{
			Name:  firstName(host.Names),
			Addr:  host.IP,
			CNAME: host.CNAME,
		}
		for _, name := range host.Names {
			record.Name = domain.EnsureTLD(name, tld)
			store.upsertDNS(record)
		}
	}
	return store
}

func (s *webStore) snapshot() webState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	leases := make([]leaseView, 0, len(s.leases))
	for _, lease := range s.leases {
		leases = append(leases, lease)
	}
	sort.Slice(leases, func(i, j int) bool {
		if leases[i].Hostname == leases[j].Hostname {
			return leases[i].Address < leases[j].Address
		}
		return leases[i].Hostname < leases[j].Hostname
	})

	dnsRecords := make([]dnsRecordView, 0, len(s.dnsRecords))
	for _, record := range s.dnsRecords {
		dnsRecords = append(dnsRecords, record)
	}
	sort.Slice(dnsRecords, func(i, j int) bool {
		return dnsRecords[i].Name < dnsRecords[j].Name
	})

	staticHosts := make([]staticHostView, len(s.staticHosts))
	copy(staticHosts, s.staticHosts)

	return webState{
		GeneratedAt: s.updatedAt,
		Counts: webCounts{
			Leases:      len(leases),
			DNSRecords:  len(dnsRecords),
			StaticHosts: len(staticHosts),
		},
		Leases:      leases,
		DNSRecords:  dnsRecords,
		StaticHosts: staticHosts,
	}
}

func (s *webStore) upsertLease(lease domain.Lease) leaseView {
	view := leaseView{
		Key:          leaseKey(lease),
		Hostname:     strings.TrimSpace(lease.Hostname),
		HardwareAddr: strings.TrimSpace(lease.HardwareAddr),
		Address:      lease.Address.String(),
		Interface:    strings.TrimSpace(lease.Interface),
		LeaseUntil:   lease.LeaseUntil.UTC(),
		UpdatedAt:    time.Now().UTC(),
	}

	s.mu.Lock()
	s.leases[view.Key] = view
	s.updatedAt = view.UpdatedAt
	s.mu.Unlock()

	return view
}

func (s *webStore) upsertStaticHost(staticHost domain.StaticHost) staticHostView {
	view := staticHostView{
		Hostname:     domain.EnsureTLD(strings.TrimSpace(staticHost.Hostname), s.tld),
		HardwareAddr: strings.TrimSpace(staticHost.HardwareAddr),
		Address:      staticHost.Address.String(),
	}

	s.mu.Lock()
	found := false
	for i, sh := range s.staticHosts {
		if sh.Hostname == view.Hostname && sh.HardwareAddr != "" {
			s.staticHosts[i] = view
			found = true
			break
		}
	}
	if !found {
		s.staticHosts = append(s.staticHosts, view)
	}
	s.updatedAt = time.Now().UTC()
	s.mu.Unlock()

	return view
}

func (s *webStore) upsertDNS(record domain.DNSRecord) dnsRecordView {
	if strings.TrimSpace(record.Name) == "" {
		return dnsRecordView{}
	}

	view := dnsRecordView{
		Name:      canonicalDNSName(record.Name),
		Address:   "",
		CNAME:     strings.TrimSpace(record.CNAME),
		UpdatedAt: time.Now().UTC(),
	}
	if record.Addr != nil && record.Addr.IsValid() {
		view.Address = record.Addr.String()
	}
	switch {
	case view.CNAME != "" && view.Address != "":
		view.Type = "A/CNAME"
	case view.CNAME != "":
		view.Type = "CNAME"
	case view.Address != "":
		view.Type = "A"
	default:
		view.Type = "unknown"
	}

	s.mu.Lock()
	s.dnsRecords[view.Name] = view
	s.updatedAt = view.UpdatedAt
	s.mu.Unlock()

	return view
}

func newWebFeed() *webFeed {
	return &webFeed{listeners: map[uint64]chan webEvent{}}
}

func (f *webFeed) subscribe() (<-chan webEvent, func()) {
	ch := make(chan webEvent, 32)

	f.mu.Lock()
	id := f.nextID
	f.nextID++
	f.listeners[id] = ch
	f.mu.Unlock()

	unsubscribe := func() {
		f.mu.Lock()
		if _, ok := f.listeners[id]; ok {
			delete(f.listeners, id)
		}
		f.mu.Unlock()
	}

	return ch, unsubscribe
}

func (f *webFeed) publish(event webEvent) {
	f.mu.Lock()
	listeners := make([]chan webEvent, 0, len(f.listeners))
	for _, ch := range f.listeners {
		listeners = append(listeners, ch)
	}
	f.mu.Unlock()

	for _, ch := range listeners {
		select {
		case ch <- event:
		default:
		}
	}
}

func leaseKey(lease domain.Lease) string {
	if key := strings.TrimSpace(lease.HardwareAddr); key != "" {
		return "hw:" + key
	}
	if key := strings.TrimSpace(lease.Hostname); key != "" {
		return "host:" + canonicalDNSName(key)
	}
	if lease.Address.IsValid() {
		return "ip:" + lease.Address.String()
	}
	return fmt.Sprintf("lease:%s", time.Now().UTC().Format(time.RFC3339Nano))
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(true)
	_ = enc.Encode(payload)
}

func writeSSE(w http.ResponseWriter, event string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "event: %s\n", event); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
		return err
	}
	return nil
}
