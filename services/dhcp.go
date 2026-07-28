package services

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/josephabbey/nettle/bus"
	"github.com/josephabbey/nettle/config"
	"github.com/josephabbey/nettle/domain"
)

type DHCPService struct {
	cfg *config.Config
	bus bus.Bus
	log *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	servers []*server4.Server
	pools   []*leasePool

	unsubscribe func()
	mu          sync.Mutex
	started     bool
}

type leasePool struct {
	name   string
	assign config.Assignment
	start  netip.Addr
	end    netip.Addr
	next   netip.Addr
	leases map[string]leaseState
	log    *slog.Logger
	bus    bus.Bus

	gateway    *netip.Addr
	dnsServers []netip.Addr
	ntp        *netip.Addr

	leasesMu sync.Mutex
	routesMu sync.RWMutex
	routes   []domain.Route

	staticByMAC  map[string]staticAssignment
	staticIPs    map[string]struct{}
}

type staticAssignment struct {
	Address  netip.Addr
	Hostname string
}

type leaseState struct {
	Address   netip.Addr
	ExpiresAt time.Time
	Hostname  string
}

func NewDHCP(cfg *config.Config, b bus.Bus, logger *slog.Logger) *DHCPService {
	if logger == nil {
		logger = slog.Default()
	}
	return &DHCPService{
		cfg: cfg,
		bus: b,
		log: logger.With("component", "dhcp"),
	}
}

func (s *DHCPService) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return nil
	}

	pools, err := s.buildPools()
	if err != nil {
		return err
	}
	s.pools = pools
	if len(s.pools) == 0 {
		s.log.Info("dhcp service skipped", "reason", "no assignments configured")
		s.started = true
		return nil
	}

	s.started = true
	s.ctx, s.cancel = context.WithCancel(ctx)

	for _, pool := range s.pools {
		ifname := pool.assign.Interface
		if ifname == "" {
			ifname = ""
		}
		server, err := server4.NewServer(ifname, &net.UDPAddr{
			IP:   net.IPv4zero,
			Port: dhcpv4.ServerPort,
		}, pool.handler)
		if err != nil {
			s.started = false
			if s.cancel != nil {
				s.cancel()
			}
			return fmt.Errorf("dhcp %s: %w", pool.name, err)
		}
		s.servers = append(s.servers, server)
		go func(name string, srv *server4.Server) {
			if err := srv.Serve(); err != nil {
				s.log.Error("dhcp server stopped", "pool", name, "error", err)
			}
		}(pool.name, server)
	}

	if s.bus != nil {
		events, unsubscribe := s.bus.Subscribe(32)
		s.unsubscribe = unsubscribe
		go s.consumeEvents(events)
	}

	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-s.ctx.Done():
				_ = s.Stop(context.Background())
				return
			case <-ticker.C:
				for _, pool := range s.pools {
					pool.expireLeases()
				}
			}
		}
	}()

	s.log.Info("dhcp service started", "servers", len(s.servers))
	return nil
}

func (s *DHCPService) Stop(ctx context.Context) error {
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
	var errs []error
	for _, srv := range s.servers {
		if err := srv.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	s.servers = nil
	s.pools = nil
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	s.log.Info("dhcp service stopped")
	return nil
}

func (s *DHCPService) buildPools() ([]*leasePool, error) {
	var pools []*leasePool
	if pool, err := newLeasePool("main", s.cfg.DHCP.Main, s.cfg.DHCP.Gateway, s.cfg.DHCP.DNS, s.cfg.DHCP.NTP, s.cfg.StaticHosts, s.bus); err != nil {
		return nil, err
	} else if pool != nil {
		pools = append(pools, pool)
	}
	if s.cfg.DHCP.Guest != nil {
		if pool, err := newLeasePool("guest", *s.cfg.DHCP.Guest, s.cfg.DHCP.Gateway, s.cfg.DHCP.DNS, s.cfg.DHCP.NTP, s.cfg.StaticHosts, s.bus); err != nil {
			return nil, err
		} else if pool != nil {
			pools = append(pools, pool)
		}
	}
	return pools, nil
}

func newLeasePool(name string, assign config.Assignment, gateway *netip.Addr, dnsServers []netip.Addr, ntp *netip.Addr, statics []config.StaticHost, b bus.Bus) (*leasePool, error) {
	if !assign.IsConfigured() {
		return nil, nil
	}
	start, end, err := assignmentBounds(assign)
	if err != nil {
		return nil, fmt.Errorf("%s assignment: %w", name, err)
	}
	if !start.Is4() || !end.Is4() {
		return nil, fmt.Errorf("%s assignment must be IPv4", name)
	}
	if assign.Lease <= 0 {
		assign.Lease = 6 * time.Hour
	}
	if assign.Interface == "" {
		assign.Interface = ""
	}

	pool := &leasePool{
		name:   name,
		assign: assign,
		start:  start,
		end:    end,
		next:   start,
		leases: map[string]leaseState{},
		log:    slog.Default().With("component", "dhcp", "pool", name),
		bus:    b,

		gateway:    gateway,
		dnsServers: dnsServers,
		ntp:        ntp,

		staticByMAC: map[string]staticAssignment{},
		staticIPs:   map[string]struct{}{},
	}

	for _, sh := range statics {
		if sh.HardwareAddr == "" || !sh.Address.IsValid() || !sh.Address.Is4() {
			continue
		}
		mac := strings.ToLower(strings.TrimSpace(sh.HardwareAddr))
		pool.staticByMAC[mac] = staticAssignment{
			Address:  sh.Address,
			Hostname: sh.Hostname,
		}
		pool.staticIPs[sh.Address.String()] = struct{}{}
	}

	return pool, nil
}

func assignmentBounds(assign config.Assignment) (netip.Addr, netip.Addr, error) {
	switch {
	case assign.Prefix != nil:
		prefix := assign.Prefix.Masked()
		start := prefix.Addr()
		end, err := prefixEnd(prefix)
		if err != nil {
			return netip.Addr{}, netip.Addr{}, err
		}
		if prefix.Addr().Is4() && prefix.Bits() < 31 {
			start = start.Next()
			end = end.Prev()
		}
		return start, end, nil
	case assign.Range != nil:
		return assign.Range.Start, assign.Range.End, nil
	default:
		return netip.Addr{}, netip.Addr{}, errors.New("missing assignment")
	}
}

func prefixEnd(prefix netip.Prefix) (netip.Addr, error) {
	base := prefix.Masked().Addr()
	bits := 32
	if base.Is6() {
		bits = 128
	}
	hostBits := bits - prefix.Bits()
	if hostBits < 0 {
		return netip.Addr{}, fmt.Errorf("invalid prefix %s", prefix)
	}
	cur := base
	for i := 0; i < hostBits; i++ {
		cur = cur.Next()
	}
	if hostBits == 0 {
		return base, nil
	}
	return cur.Prev(), nil
}

func (s *DHCPService) consumeEvents(events <-chan bus.Event) {
	for {
		select {
		case <-s.ctx.Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			switch ev := event.(type) {
			case domain.RouteAnnounced:
				for _, pool := range s.pools {
					pool.addRoute(ev.Route)
				}
			}
		}
	}
}

func (p *leasePool) handler(conn net.PacketConn, peer net.Addr, m *dhcpv4.DHCPv4) {
	p.log.Info("dhcp packet", "peer", peer.String(), "message", m.MessageType().String(), "summary", m.Summary())

	if m.MessageType() == dhcpv4.MessageTypeRelease {
		key := p.hardwareAddr(m)
		p.leasesMu.Lock()
		if key == "" {
			key = fmt.Sprintf("%x", m.TransactionID)
		}
		delete(p.leases, key)
		p.leasesMu.Unlock()
		p.log.Info("dhcp release", "mac", key)
		return
	}

	if m.MessageType() != dhcpv4.MessageTypeDiscover && m.MessageType() != dhcpv4.MessageTypeRequest {
		return
	}

	ip, err := p.allocate(m)
	if err != nil {
		p.log.Warn("lease allocation failed", "error", err)
		return
	}

	hostname := strings.TrimSpace(m.HostName())
	if hostname != "" && p.bus != nil {
		_ = p.bus.Publish(context.Background(), domain.DNSRecordUpserted{
			Record: domain.DNSRecord{
				Name: hostname,
				Addr: addrPtr(ip),
			},
		})
	}
	if p.bus != nil {
		_ = p.bus.Publish(context.Background(), domain.DHCPLeaseAssigned{
			Lease: domain.Lease{
				Hostname:     hostname,
				HardwareAddr: p.hardwareAddr(m),
				Address:      ip,
				Interface:    p.assign.Interface,
				LeaseUntil:   time.Now().Add(p.assign.Lease),
			},
		})
	}

	replyType := dhcpv4.MessageTypeAck
	if m.MessageType() == dhcpv4.MessageTypeDiscover {
		replyType = dhcpv4.MessageTypeOffer
	}

	modifiers := []dhcpv4.Modifier{
		dhcpv4.WithMessageType(replyType),
		dhcpv4.WithYourIP(net.IP(ip.AsSlice())),
		dhcpv4.WithLeaseTime(uint32(p.assign.Lease / time.Second)),
	}

	if p.gateway != nil {
		modifiers = append(modifiers, dhcpv4.WithRouter(net.IP(p.gateway.AsSlice())))
	}
	if len(p.dnsServers) > 0 {
		dnsIPs := make([]net.IP, len(p.dnsServers))
		for i, dns := range p.dnsServers {
			dnsIPs[i] = net.IP(dns.AsSlice())
		}
		modifiers = append(modifiers, dhcpv4.WithDNS(dnsIPs...))
	}
	if p.ntp != nil {
		ntpIP := net.IP(p.ntp.AsSlice()).To4()
		if ntpIP != nil {
			modifiers = append(modifiers, dhcpv4.WithOption(dhcpv4.OptNTPServers(ntpIP)))
		}
	}
	if p.assign.Prefix != nil {
		mask := net.CIDRMask(p.assign.Prefix.Bits(), 32)
		modifiers = append(modifiers, dhcpv4.WithNetmask(mask))
	}

	p.routesMu.RLock()
	if len(p.routes) > 0 {
		dhcpRoutes := p.toDHCPRoutes()
		if len(dhcpRoutes) > 0 {
			modifiers = append(modifiers, dhcpv4.WithOption(dhcpv4.OptClasslessStaticRoute(dhcpRoutes...)))
		}
	}
	p.routesMu.RUnlock()

	reply, err := dhcpv4.NewReplyFromRequest(m, modifiers...)
	if err != nil {
		p.log.Warn("failed to build dhcp reply", "error", err)
		return
	}
	_, _ = conn.WriteTo(reply.ToBytes(), peer)
}

func (p *leasePool) allocate(req *dhcpv4.DHCPv4) (netip.Addr, error) {
	mac := strings.ToLower(p.hardwareAddr(req))
	key := mac
	if key == "" {
		key = fmt.Sprintf("%x", req.TransactionID)
	}

	now := time.Now()

	if sa, ok := p.staticByMAC[mac]; ok && p.addrInRange(sa.Address) {
		p.leasesMu.Lock()
		p.leases[key] = leaseState{
			Address:   sa.Address,
			ExpiresAt: now.Add(p.assign.Lease),
			Hostname:  sa.Hostname,
		}
		p.leasesMu.Unlock()
		return sa.Address, nil
	}

	if lease, ok := p.leases[key]; ok && now.Before(lease.ExpiresAt) {
		return lease.Address, nil
	}

	for candidate := p.next; candidate.IsValid() && candidate.Compare(p.end) <= 0; candidate = candidate.Next() {
		if !p.taken(candidate, now) && !p.isStatic(candidate) {
			p.leases[key] = leaseState{
				Address:   candidate,
				ExpiresAt: now.Add(p.assign.Lease),
				Hostname:  req.HostName(),
			}
			p.next = candidate.Next()
			return candidate, nil
		}
	}
	return netip.Addr{}, errors.New("lease pool exhausted")
}

func (p *leasePool) addrInRange(addr netip.Addr) bool {
	return addr.Compare(p.start) >= 0 && addr.Compare(p.end) <= 0
}

func (p *leasePool) isStatic(addr netip.Addr) bool {
	_, ok := p.staticIPs[addr.String()]
	return ok
}

func (p *leasePool) taken(addr netip.Addr, now time.Time) bool {
	for _, lease := range p.leases {
		if lease.Address == addr && now.Before(lease.ExpiresAt) {
			return true
		}
	}
	return false
}

func (p *leasePool) hardwareAddr(req *dhcpv4.DHCPv4) string {
	if len(req.ClientHWAddr) == 0 {
		return ""
	}
	return req.ClientHWAddr.String()
}

func addrPtr(addr netip.Addr) *netip.Addr {
	if !addr.IsValid() {
		return nil
	}
	return &addr
}

func (p *leasePool) addRoute(route domain.Route) {
	p.routesMu.Lock()
	defer p.routesMu.Unlock()
	for i, r := range p.routes {
		if r.Prefix == route.Prefix {
			p.routes[i] = route
			return
		}
	}
	p.routes = append(p.routes, route)
}

func (p *leasePool) toDHCPRoutes() []*dhcpv4.Route {
	var dhcpRoutes []*dhcpv4.Route
	for _, route := range p.routes {
		if !route.Prefix.IsValid() || !route.Prefix.Addr().Is4() {
			continue
		}
		if route.Gateway == nil || !route.Gateway.Is4() {
			continue
		}
		mask := net.CIDRMask(route.Prefix.Bits(), 32)
		dest := &net.IPNet{
			IP:   net.IP(route.Prefix.Addr().AsSlice()),
			Mask: mask,
		}
		dhcpRoutes = append(dhcpRoutes, &dhcpv4.Route{
			Dest:   dest,
			Router: net.IP(route.Gateway.AsSlice()),
		})
	}
	return dhcpRoutes
}

func (p *leasePool) expireLeases() {
	now := time.Now()
	p.leasesMu.Lock()
	defer p.leasesMu.Unlock()
	for key, lease := range p.leases {
		if now.After(lease.ExpiresAt) {
			delete(p.leases, key)
		}
	}
}
