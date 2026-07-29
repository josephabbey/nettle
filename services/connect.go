package services

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/josephabbey/nettle/bus"
	"github.com/josephabbey/nettle/config"
	"github.com/josephabbey/nettle/domain"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const connectStateDir = "/var/lib/nettle/connect"

type connectTunnel struct {
	target    string
	ifaceName string
	noDNS     bool

	gluePubKey string
	link       netlink.Link

	remotePubKey string
	remotePrefix *netip.Prefix
	endpoint     string

	established bool
}

type glueState struct {
	address    string
	privateKey wgtypes.Key
	publicKey  string
	tunnels    map[string]*connectTunnel
}

type ConnectService struct {
	cfg *config.Config
	bus bus.Bus
	log *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	started bool

	wgClient *wgctrl.Client
	glues    map[string]*glueState
	dns      *DNSService

	unsubscribe func()
}

func (s *ConnectService) SetDNS(dns *DNSService) {
	s.dns = dns
}

func NewConnect(cfg *config.Config, b bus.Bus, logger *slog.Logger) *ConnectService {
	if logger == nil {
		logger = slog.Default()
	}
	return &ConnectService{
		cfg:   cfg,
		bus:   b,
		log:   logger.With("component", "connect"),
		glues: make(map[string]*glueState),
	}
}

func (s *ConnectService) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return nil
	}

	if len(s.cfg.Glue) == 0 {
		s.log.Info("connect service skipped", "reason", "no glue configured")
		s.started = true
		return nil
	}

	s.started = true
	s.ctx, s.cancel = context.WithCancel(ctx)

	cl, err := wgctrl.New()
	if err != nil {
		s.started = false
		return fmt.Errorf("connect: wgctrl: %w", err)
	}
	s.wgClient = cl

	if err := os.MkdirAll(connectStateDir, 0700); err != nil {
		s.wgClient.Close()
		s.started = false
		return fmt.Errorf("connect: mkdir: %w", err)
	}

	for _, glue := range s.cfg.Glue {
		if err := s.setupGlue(glue); err != nil {
			s.log.Error("failed to setup glue", "address", glue.Address, "error", err)
		}
	}

	if s.bus != nil {
		events, unsubscribe := s.bus.Subscribe(32)
		s.unsubscribe = unsubscribe
		go s.consumeEvents(events)
	}

	s.log.Info("connect service started", "glue", len(s.cfg.Glue))
	return nil
}

func (s *ConnectService) Stop(ctx context.Context) error {
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
	if s.wgClient != nil {
		s.wgClient.Close()
		s.wgClient = nil
	}
	for _, glue := range s.glues {
		for _, tun := range glue.tunnels {
			s.teardownTunnel(tun)
		}
	}
	s.log.Info("connect service stopped")
	return nil
}

func ifaceNameForTarget(target string) string {
	name := strings.TrimSpace(target)
	name = strings.Split(name, ".")[0]
	name = strings.Split(name, ":")[0]
	if len(name) > 10 {
		name = name[:10]
	}
	return "nettle-" + name
}

func (s *ConnectService) setupGlue(glue config.GlueConfig) error {
	if strings.TrimSpace(glue.Address) == "" {
		return errors.New("empty glue address")
	}

	gs := &glueState{
		address: glue.Address,
		tunnels: make(map[string]*connectTunnel),
	}

	keyStr, err := s.loadOrGenerateGlueKey(glue.Address)
	if err != nil {
		return fmt.Errorf("glue key %s: %w", glue.Address, err)
	}

	key, err := wgtypes.ParseKey(keyStr)
	if err != nil {
		return fmt.Errorf("parse glue key: %w", err)
	}
	gs.privateKey = key
	gs.publicKey = key.PublicKey().String()

	for _, conn := range glue.Connections {
		target := strings.TrimSpace(conn.Target)
		if target == "" {
			continue
		}

		tun := &connectTunnel{
			target:    target,
			ifaceName: ifaceNameForTarget(target),
			noDNS:     conn.NoDNS,
		}

		if err := s.createTunnel(tun, gs); err != nil {
			s.log.Error("failed to create tunnel", "target", target, "error", err)
			continue
		}

		gs.tunnels[target] = tun
		s.log.Info("connect tunnel created", "target", target, "interface", tun.ifaceName)
	}

	s.glues[glue.Address] = gs
	return nil
}

func (s *ConnectService) loadOrGenerateGlueKey(address string) (string, error) {
	keyPath := filepath.Join(connectStateDir, sanitizeAddr(address)+"-key")

	data, err := os.ReadFile(keyPath)
	if err == nil {
		privStr := strings.TrimSpace(string(data))
		if privStr != "" {
			return privStr, nil
		}
	}
	if err != nil && !os.IsNotExist(err) {
		return "", fmt.Errorf("read key: %w", err)
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", fmt.Errorf("generate key: %w", err)
	}
	privStr := key.String()

	if err := os.WriteFile(keyPath, []byte(privStr+"\n"), 0600); err != nil {
		return "", fmt.Errorf("write key: %w", err)
	}

	s.log.Info("generated new glue key", "address", address, "pubkey", key.PublicKey().String())
	return privStr, nil
}

func sanitizeAddr(addr string) string {
	addr = strings.TrimPrefix(addr, "https://")
	addr = strings.TrimPrefix(addr, "http://")
	addr = strings.ReplaceAll(addr, ":", "-")
	addr = strings.ReplaceAll(addr, "/", "-")
	return addr
}

func (s *ConnectService) createTunnel(tun *connectTunnel, gs *glueState) error {
	la := netlink.NewLinkAttrs()
	la.Name = tun.ifaceName
	link := &netlink.GenericLink{
		LinkAttrs: la,
		LinkType:  "wireguard",
	}
	if err := netlink.LinkAdd(link); err != nil {
		if !strings.Contains(err.Error(), "exists") {
			return fmt.Errorf("link add: %w", err)
		}
		existing, err := netlink.LinkByName(tun.ifaceName)
		if err != nil {
			return fmt.Errorf("link by name: %w", err)
		}
		tun.link = existing
	} else {
		tun.link = link
	}

	tun.gluePubKey = gs.publicKey

	if s.wgClient != nil {
		port := 0
		if err := s.wgClient.ConfigureDevice(tun.ifaceName, wgtypes.Config{
			PrivateKey: &gs.privateKey,
			ListenPort: &port,
		}); err != nil {
			return fmt.Errorf("configure tunnel device: %w", err)
		}
	}

	_ = netlink.LinkSetUp(link)

	return nil
}

func (s *ConnectService) teardownTunnel(tun *connectTunnel) {
	if tun.link != nil {
		_ = netlink.LinkDel(tun.link)
	}
}

func (s *ConnectService) SetRemotePeer(target, publicKey, endpoint string, remotePrefix netip.Prefix) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started {
		return errors.New("connect service not started")
	}

	for _, gs := range s.glues {
		tun, ok := gs.tunnels[target]
		if !ok {
			continue
		}

		if s.wgClient == nil {
			return errors.New("wgctrl not initialized")
		}

		pk, err := wgtypes.ParseKey(publicKey)
		if err != nil {
			return fmt.Errorf("parse public key: %w", err)
		}

		ipNet := net.IPNet{
			IP:   net.IP(remotePrefix.Addr().AsSlice()),
			Mask: net.CIDRMask(remotePrefix.Bits(), 32),
		}

		epStr := endpoint
		if !strings.Contains(epStr, ":") {
			epStr = endpoint + ":51820"
		}
		ep, err := net.ResolveUDPAddr("udp", epStr)
		if err != nil {
			return fmt.Errorf("resolve endpoint: %w", err)
		}

		if err := s.wgClient.ConfigureDevice(tun.ifaceName, wgtypes.Config{
			Peers: []wgtypes.PeerConfig{{
				PublicKey:  pk,
				Endpoint:   ep,
				AllowedIPs: []net.IPNet{ipNet},
			}},
		}); err != nil {
			return fmt.Errorf("configure peer: %w", err)
		}

		tun.remotePubKey = publicKey
		tun.remotePrefix = &remotePrefix
		tun.endpoint = endpoint
		tun.established = true

		s.addRemoteRoute(tun, remotePrefix)
		s.announceRoute(remotePrefix)

		if !tun.noDNS {
			s.registerDNS(target, remotePrefix)
		}

		s.log.Info("connect peer configured",
			"target", target,
			"pubkey", publicKey[:16]+"...",
			"prefix", remotePrefix.String(),
		)
		return nil
	}

	return fmt.Errorf("no tunnel found for target %q", target)
}

func (s *ConnectService) addRemoteRoute(tun *connectTunnel, prefix netip.Prefix) {
	link, err := netlink.LinkByName(tun.ifaceName)
	if err != nil {
		s.log.Warn("route: link not found", "interface", tun.ifaceName, "error", err)
		return
	}

	route := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       &net.IPNet{IP: net.IP(prefix.Addr().AsSlice()), Mask: net.CIDRMask(prefix.Bits(), 32)},
	}

	if err := netlink.RouteAdd(route); err != nil {
		if !strings.Contains(err.Error(), "exists") {
			s.log.Warn("route add failed", "prefix", prefix.String(), "error", err)
		}
	}
}

func (s *ConnectService) announceRoute(prefix netip.Prefix) {
	if s.bus == nil {
		return
	}
	_ = s.bus.Publish(context.Background(), domain.RouteAnnounced{
		Route: domain.Route{
			Prefix: prefix,
		},
	})
	s.log.Info("announced connect route", "prefix", prefix.String())
}

func (s *ConnectService) registerDNS(target string, prefix netip.Prefix) {
	addr := prefix.Addr()
	if s.dns != nil {
		s.dns.AddUpstream(target, addr)
	}
	if s.bus != nil {
		_ = s.bus.Publish(context.Background(), domain.DNSRecordUpserted{
			Record: domain.DNSRecord{
				Name: target,
				Addr: addrPtr(addr),
			},
		})
	}
	s.log.Info("registered connect dns upstream", "target", target, "address", addr.String())
}

func (s *ConnectService) GluePublicKey(address string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if gs, ok := s.glues[address]; ok {
		return gs.publicKey
	}
	return ""
}

func (s *ConnectService) ListTunnels() []domain.Peer {
	s.mu.Lock()
	defer s.mu.Unlock()

	var result []domain.Peer
	for addr, gs := range s.glues {
		for target, tun := range gs.tunnels {
			connected := false
			if s.wgClient != nil {
				dev, err := s.wgClient.Device(tun.ifaceName)
				if err == nil && len(dev.Peers) > 0 {
					connected = !dev.Peers[0].LastHandshakeTime.IsZero()
				}
			}

			result = append(result, domain.Peer{
				Name:      fmt.Sprintf("%s → %s", addr, target),
				Connected: connected,
				Endpoint:  tun.endpoint,
				PublicKey: tun.remotePubKey,
			})
		}
	}
	return result
}

func (s *ConnectService) consumeEvents(events <-chan bus.Event) {
	for {
		select {
		case <-s.ctx.Done():
			return
		case _, ok := <-events:
			if !ok {
				return
			}
		}
	}
}

func (s *ConnectService) ConnectionInfo(glueAddress string) map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()

	gs, ok := s.glues[glueAddress]
	if !ok {
		return nil
	}

	info := map[string]any{
		"address":   gs.address,
		"publicKey": gs.publicKey,
	}

	var localPrefixes []string
	if s.cfg.DHCP.Main.Prefix != nil {
		localPrefixes = append(localPrefixes, s.cfg.DHCP.Main.Prefix.String())
	}
	if s.cfg.DHCP.Main.Range != nil {
		localPrefixes = append(localPrefixes, fmt.Sprintf("%s-%s", s.cfg.DHCP.Main.Range.Start, s.cfg.DHCP.Main.Range.End))
	}
	if s.cfg.VPN.Assign != nil {
		localPrefixes = append(localPrefixes, s.cfg.VPN.Assign.String())
	}
	info["localPrefixes"] = localPrefixes

	return info
}

func (s *ConnectService) TunnelsJSON() ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	type tunnelView struct {
		Address      string `json:"address"`
		Target       string `json:"target"`
		Interface    string `json:"interface"`
		PublicKey    string `json:"publicKey"`
		Established  bool   `json:"established"`
		RemotePrefix string `json:"remotePrefix,omitempty"`
	}

	var tunnels []tunnelView
	for addr, gs := range s.glues {
		for target, tun := range gs.tunnels {
			tv := tunnelView{
				Address:     addr,
				Target:      target,
				Interface:   tun.ifaceName,
				PublicKey:   tun.gluePubKey,
				Established: tun.established,
			}
			if tun.remotePrefix != nil {
				tv.RemotePrefix = tun.remotePrefix.String()
			}
			tunnels = append(tunnels, tv)
		}
	}
	if tunnels == nil {
		tunnels = []tunnelView{}
	}
	return json.Marshal(tunnels)
}
