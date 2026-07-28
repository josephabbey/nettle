package services

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"

	"github.com/josephabbey/nettle/bus"
	"github.com/josephabbey/nettle/config"
	"github.com/josephabbey/nettle/domain"
	"github.com/miekg/dns"
)

type DNSService struct {
	cfg *config.Config
	bus bus.Bus
	log *slog.Logger

	server *dns.Server
	ctx    context.Context
	cancel context.CancelFunc

	store       *dnsRecordStore
	unsubscribe func()
	mu          sync.Mutex
	started     bool
}

type dnsRecordStore struct {
	mu        sync.RWMutex
	exact     map[string]domain.DNSRecord
	wildcards []wildcardRecord
}

type wildcardRecord struct {
	suffix string
	record domain.DNSRecord
}

func NewDNS(cfg *config.Config, b bus.Bus, logger *slog.Logger) *DNSService {
	if logger == nil {
		logger = slog.Default()
	}
	return &DNSService{
		cfg:   cfg,
		bus:   b,
		log:   logger.With("component", "dns"),
		store: newDNSRecordStore(cfg.Hosts, cfg.Global.TLD),
	}
}

func newDNSRecordStore(hosts []config.HostRecord, tld string) *dnsRecordStore {
	store := &dnsRecordStore{exact: map[string]domain.DNSRecord{}}
	for _, host := range hosts {
		record := domain.DNSRecord{
			Name:  firstName(host.Names),
			Addr:  host.IP,
			CNAME: host.CNAME,
		}
		for _, name := range host.Names {
			store.put(ensureTLD(name, tld), record)
		}
	}
	return store
}

func firstName(names []string) string {
	if len(names) == 0 {
		return ""
	}
	return names[0]
}

func canonicalDNSName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

func ensureTLD(name string, tld string) string {
	if !strings.Contains(name, ".") {
		return name + "." + tld
	}
	return name
}

func (s *dnsRecordStore) put(name string, record domain.DNSRecord) {
	canonical := canonicalDNSName(name)
	s.mu.Lock()
	defer s.mu.Unlock()
	if strings.HasPrefix(canonical, "*.") {
		s.wildcards = append(s.wildcards, wildcardRecord{
			suffix: strings.TrimPrefix(canonical, "*."),
			record: record,
		})
		return
	}
	s.exact[canonical] = record
}

func (s *dnsRecordStore) upsert(record domain.DNSRecord) {
	s.put(record.Name, record)
}

func (s *dnsRecordStore) lookup(name string) (domain.DNSRecord, bool) {
	canonical := canonicalDNSName(name)
	s.mu.RLock()
	defer s.mu.RUnlock()

	if record, ok := s.exact[canonical]; ok {
		return record, true
	}
	for _, wild := range s.wildcards {
		if strings.HasSuffix(canonical, "."+wild.suffix) && canonical != wild.suffix {
			return wild.record, true
		}
	}
	return domain.DNSRecord{}, false
}

func (s *DNSService) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return nil
	}
	s.started = true
	s.ctx, s.cancel = context.WithCancel(ctx)

	port := s.cfg.DNS.Port
	if port == 0 {
		port = 53
	}
	network := s.cfg.DNS.Network
	if network == "" {
		network = "udp"
	}
	s.server = &dns.Server{
		Addr:    net.JoinHostPort("0.0.0.0", strconv.Itoa(port)),
		Net:     network,
		Handler: dns.HandlerFunc(s.serveDNS),
	}

	if s.bus != nil {
		events, unsubscribe := s.bus.Subscribe(32)
		s.unsubscribe = unsubscribe
		go s.consumeEvents(events)
	}

	go func() {
		<-s.ctx.Done()
		_ = s.Stop(context.Background())
	}()

	go func() {
		if err := s.server.ListenAndServe(); err != nil {
			s.log.Error("dns server stopped", "error", err)
		}
	}()

	s.log.Info("dns service started", "addr", s.server.Addr, "network", s.server.Net)
	return nil
}

func (s *DNSService) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started {
		return nil
	}
	s.started = false
	if s.unsubscribe != nil {
		s.unsubscribe()
		s.unsubscribe = nil
	}
	if s.cancel != nil {
		s.cancel()
		s.cancel = nil
	}
	if s.server != nil {
		err := s.server.Shutdown()
		s.server = nil
		if err != nil {
			return err
		}
	}
	s.log.Info("dns service stopped")
	return nil
}

func (s *DNSService) consumeEvents(events <-chan bus.Event) {
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
				if ev.Record.Name != "" {
					s.store.upsert(ev.Record)
				}
			}
		}
	}
}

func (s *DNSService) serveDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Authoritative = true

	if len(r.Question) == 0 {
		msg.Rcode = dns.RcodeFormatError
		_ = w.WriteMsg(msg)
		return
	}

	q := r.Question[0]

	if s.isBlocked(q.Name) {
		msg.Rcode = dns.RcodeNameError
		_ = w.WriteMsg(msg)
		return
	}

	if record, ok := s.store.lookup(q.Name); ok {
		if rr := recordToRR(q.Name, q.Qtype, record); len(rr) > 0 {
			msg.Answer = append(msg.Answer, rr...)
			_ = w.WriteMsg(msg)
			return
		}
	}

	if resp, ok := s.forwardUpstream(r); ok {
		_ = w.WriteMsg(resp)
		return
	}

	msg.Rcode = dns.RcodeNameError
	_ = w.WriteMsg(msg)
}

func (s *DNSService) isBlocked(name string) bool {
	name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
	for _, blocked := range s.cfg.DNS.Blocked {
		b := strings.ToLower(strings.TrimSpace(blocked))
		if strings.HasPrefix(b, "*.") {
			suffix := b[1:]
			if strings.HasSuffix(name, suffix) {
				return true
			}
		} else if name == b || strings.HasSuffix(name, "."+b) {
			return true
		}
	}
	return false
}

func (s *DNSService) forwardUpstream(r *dns.Msg) (*dns.Msg, bool) {
	if len(r.Question) == 0 {
		return nil, false
	}
	q := r.Question[0]
	name := strings.ToLower(strings.TrimSuffix(q.Name, "."))

	if len(s.cfg.DNS.RecursiveUpstreams) > 0 {
		for zone, addr := range s.cfg.DNS.RecursiveUpstreams {
			zone = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(zone), "."))
			if name == zone || strings.HasSuffix(name, "."+zone) {
				return s.forwardTo(addr, r)
			}
		}
	}

	for _, upstream := range s.cfg.DNS.Upstreams {
		if resp, ok := s.forwardTo(upstream, r); ok {
			return resp, true
		}
	}
	return nil, false
}

func (s *DNSService) forwardTo(upstream netip.Addr, r *dns.Msg) (*dns.Msg, bool) {
	client := &dns.Client{Net: s.cfg.DNS.Network}
	resp, _, err := client.Exchange(r, net.JoinHostPort(upstream.String(), "53"))
	if err != nil {
		s.log.Debug("dns upstream failed", "upstream", upstream.String(), "error", err)
		return nil, false
	}
	return resp, true
}

func recordToRR(qname string, qtype uint16, record domain.DNSRecord) []dns.RR {
	switch qtype {
	case dns.TypeA:
		if record.Addr == nil || !record.Addr.Is4() {
			return nil
		}
		return []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   net.IP(record.Addr.AsSlice()),
		}}
	case dns.TypeAAAA:
		if record.Addr == nil || !record.Addr.Is6() {
			return nil
		}
		return []dns.RR{&dns.AAAA{
			Hdr:  dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
			AAAA: net.IP(record.Addr.AsSlice()),
		}}
	case dns.TypeCNAME:
		if record.CNAME == "" {
			return nil
		}
		return []dns.RR{&dns.CNAME{
			Hdr:    dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
			Target: dns.Fqdn(record.CNAME),
		}}
	default:
		if record.CNAME != "" {
			return []dns.RR{&dns.CNAME{
				Hdr:    dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: dns.Fqdn(record.CNAME),
			}}
		}
		if record.Addr != nil {
			if record.Addr.Is4() {
				return []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   net.IP(record.Addr.AsSlice()),
				}}
			}
			if record.Addr.Is6() {
				return []dns.RR{&dns.AAAA{
					Hdr:  dns.RR_Header{Name: dns.Fqdn(qname), Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 60},
					AAAA: net.IP(record.Addr.AsSlice()),
				}}
			}
		}
		return nil
	}
}
