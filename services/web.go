package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
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

	store   *webStore
	feed    *webFeed
	vpn     *VPNService
	connect *ConnectService
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

func (s *WebService) SetVPN(vpn *VPNService) {
	s.vpn = vpn
}

func (s *WebService) SetConnect(connect *ConnectService) {
	s.connect = connect
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
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	r.GET("/", s.serveIndex)
	r.GET("/assets/*filepath", gin.WrapH(http.StripPrefix("/assets/", http.FileServer(http.FS(webAssetFS)))))
	r.GET("/healthz", s.serveHealth)
	r.GET("/api/state", s.serveState)
	r.GET("/api/leases", s.serveLeases)
	r.GET("/api/dns-records", s.serveDNSRecords)
	r.GET("/api/static-hosts", s.serveStaticHosts)
	r.GET("/events", s.serveEvents)
	r.GET("/api/network", s.serveNetwork)
	r.GET("/api/user", s.serveUser)
	if s.vpn != nil {
		r.GET("/api/vpn/peers", s.serveVPNPeers)
		r.DELETE("/api/vpn/peers", s.serveVPNPeers)
		r.POST("/api/vpn/generate", s.serveVPNGenerate)
	}
	if s.connect != nil {
		r.GET("/api/connect/tunnels", s.serveConnectTunnels)
		r.POST("/api/connect/pair", s.serveConnectPair)
	}

	if s.cfg.Web.OIDC != nil {
		r.Use(s.oidcMiddleware())
	}

	return r
}

func (s *WebService) oidcMiddleware() gin.HandlerFunc {
	headerName := s.cfg.Web.OIDC.UserHeader
	return func(c *gin.Context) {
		if s.isPublicPath(c.Request.URL.Path) {
			c.Next()
			return
		}
		user := strings.TrimSpace(c.GetHeader(headerName))
		if user == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "message": "authenticate through the reverse proxy"})
			c.Abort()
			return
		}
		c.Set("user", user)
		c.Next()
	}
}

func (s *WebService) isPublicPath(path string) bool {
	return path == "/healthz"
}

func (s *WebService) serveIndex(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Header("Cache-Control", "no-store")
	c.Writer.Write(webIndexHTML)
}

func (s *WebService) serveUser(c *gin.Context) {
	user, _ := c.Get("user")
	userStr, _ := user.(string)
	c.JSON(http.StatusOK, gin.H{
		"authenticated": userStr != "",
		"user":          userStr,
		"oidc":          s.cfg.Web.OIDC != nil,
	})
}

func (s *WebService) serveHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *WebService) serveState(c *gin.Context) {
	c.JSON(http.StatusOK, s.store.snapshot())
}

func (s *WebService) serveLeases(c *gin.Context) {
	c.JSON(http.StatusOK, s.store.snapshot().Leases)
}

func (s *WebService) serveDNSRecords(c *gin.Context) {
	c.JSON(http.StatusOK, s.store.snapshot().DNSRecords)
}

func (s *WebService) serveStaticHosts(c *gin.Context) {
	c.JSON(http.StatusOK, s.store.snapshot().StaticHosts)
}

func (s *WebService) serveEvents(c *gin.Context) {
	flusher, ok := c.Writer.(http.Flusher)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "streaming unsupported"})
		return
	}

	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache, no-store, must-revalidate")
	c.Header("Connection", "keep-alive")
	c.Header("X-Accel-Buffering", "no")

	events, unsubscribe := s.feed.subscribe()
	defer unsubscribe()

	data, _ := json.Marshal(s.store.snapshot())
	fmt.Fprintf(c.Writer, "event: snapshot\ndata: %s\n\n", data)
	flusher.Flush()

	keepAlive := time.NewTicker(25 * time.Second)
	defer keepAlive.Stop()

	for {
		select {
		case <-c.Request.Context().Done():
			return
		case <-keepAlive.C:
			fmt.Fprint(c.Writer, ": ping\n\n")
			flusher.Flush()
		case event, ok := <-events:
			if !ok {
				return
			}
			data, _ := json.Marshal(event.Data)
			fmt.Fprintf(c.Writer, "event: %s\ndata: %s\n\n", event.Type, data)
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
	store.loadPersistedLeases(cfg.DHCP.Main.LeasesFile, cfg.DHCP.Main.Interface, tld)
	if cfg.DHCP.Guest != nil {
		store.loadPersistedLeases(cfg.DHCP.Guest.LeasesFile, cfg.DHCP.Guest.Interface, tld)
	}
	return store
}

func (s *webStore) loadPersistedLeases(leasesFile, iface, tld string) {
	if leasesFile == "" {
		return
	}
	data, err := os.ReadFile(leasesFile)
	if err != nil {
		return
	}
	var pd persistData
	if err := json.Unmarshal(data, &pd); err != nil {
		return
	}
	if pd.Version != 1 {
		return
	}
	now := time.Now()
	for key, pl := range pd.Leases {
		addr, err := netip.ParseAddr(pl.Address)
		if err != nil {
			continue
		}
		expiresAt, err := time.Parse(time.RFC3339, pl.ExpiresAt)
		if err != nil {
			continue
		}
		if now.After(expiresAt) {
			continue
		}
		s.leases["hw:"+key] = leaseView{
			Key:          "hw:" + key,
			Hostname:     strings.TrimSpace(pl.Hostname),
			HardwareAddr: key,
			Address:      addr.String(),
			Interface:    iface,
			LeaseUntil:   expiresAt.UTC(),
			UpdatedAt:    now.UTC(),
		}
		if hostname := strings.TrimSpace(pl.Hostname); hostname != "" {
			dnsName := domain.EnsureTLD(hostname, tld)
			s.dnsRecords[dnsName] = dnsRecordView{
				Name:      canonicalDNSName(dnsName),
				Address:   addr.String(),
				Type:      "A",
				UpdatedAt: now.UTC(),
			}
		}
	}
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

func (s *WebService) serveNetwork(c *gin.Context) {
	state := s.store.snapshot()

	var vpnPeers []domain.Peer
	if s.vpn != nil {
		vpnPeers = s.vpn.ListPeers()
	}
	if vpnPeers == nil {
		vpnPeers = []domain.Peer{}
	}

	var connectTunnels []domain.Peer
	if s.connect != nil {
		connectTunnels = s.connect.ListTunnels()
	}
	if connectTunnels == nil {
		connectTunnels = []domain.Peer{}
	}

	c.JSON(http.StatusOK, gin.H{
		"leases":  state.Leases,
		"vpn":     vpnPeers,
		"connect": connectTunnels,
		"dns":     state.DNSRecords,
	})
}

func (s *WebService) serveConnectTunnels(c *gin.Context) {
	if s.connect == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "connect not configured"})
		return
	}
	peers := s.connect.ListTunnels()
	if peers == nil {
		peers = []domain.Peer{}
	}
	info := []map[string]any{}
	for _, addr := range s.cfg.Glue {
		connInfo := s.connect.ConnectionInfo(addr.Address)
		if connInfo != nil {
			info = append(info, connInfo)
		}
	}
	tunnelsJSON, err := s.connect.TunnelsJSON()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	var tunnels []any
	_ = json.Unmarshal(tunnelsJSON, &tunnels)

	c.JSON(http.StatusOK, gin.H{
		"glue":    info,
		"tunnels": tunnels,
		"peers":   peers,
	})
}

func (s *WebService) serveConnectPair(c *gin.Context) {
	if s.connect == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "connect not configured"})
		return
	}

	var req struct {
		Target       string `json:"target"`
		PublicKey    string `json:"publicKey"`
		Endpoint     string `json:"endpoint"`
		RemotePrefix string `json:"remotePrefix"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if req.Target == "" || req.PublicKey == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "target and publicKey required"})
		return
	}

	prefix, err := netip.ParsePrefix(req.RemotePrefix)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid remotePrefix"})
		return
	}

	endpoint := req.Endpoint
	if endpoint == "" {
		endpoint = req.Target
	}

	if err := s.connect.SetRemotePeer(req.Target, req.PublicKey, endpoint, prefix); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "paired"})
}

func (s *WebService) serveVPNPeers(c *gin.Context) {
	if s.vpn == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "vpn not configured"})
		return
	}
	switch c.Request.Method {
	case http.MethodGet:
		peers := s.vpn.ListPeers()
		if peers == nil {
			peers = []domain.Peer{}
		}
		c.JSON(http.StatusOK, gin.H{
			"serverPubKey": s.vpn.ServerPublicKey(),
			"peers":        peers,
		})
	case http.MethodDelete:
		var req struct {
			PublicKey string `json:"publicKey"`
		}
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
			return
		}
		if err := s.vpn.RemovePeer(req.PublicKey); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"status": "removed"})
	default:
		c.JSON(http.StatusMethodNotAllowed, gin.H{"error": "method not allowed"})
	}
}

func (s *WebService) serveVPNGenerate(c *gin.Context) {
	if s.vpn == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "vpn not configured"})
		return
	}

	var req struct {
		Name     string `json:"name"`
		Endpoint string `json:"endpoint"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if req.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if req.Endpoint == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "endpoint is required"})
		return
	}

	cfg, privKey, err := s.vpn.GenerateClientConfig(req.Name, req.Endpoint)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"config":     cfg,
		"name":       req.Name,
		"privateKey": privKey,
	})
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
