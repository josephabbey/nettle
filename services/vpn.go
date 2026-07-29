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
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/josephabbey/nettle/bus"
	"github.com/josephabbey/nettle/config"
	"github.com/josephabbey/nettle/domain"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/wgctrl"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

const (
	vpnIface     = "nettle-vpn"
	vpnPort      = 51820
	vpnStateDir  = "/var/lib/nettle/vpn"
	vpnKeyFile   = "server-private"
	vpnPeersFile = "peers.json"

	iptablesNAT    = "NETTLE_VPN_NAT"
	iptablesFwdIn  = "NETTLE_VPN_FWD_IN"
	iptablesFwdOut = "NETTLE_VPN_FWD_OUT"
)

type vpnPeerState struct {
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
	Address   string `json:"address"`
	CreatedAt string `json:"createdAt"`
}

type VPNService struct {
	cfg *config.Config
	bus bus.Bus
	log *slog.Logger

	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	started bool

	ifaceName    string
	listenPort   int
	serverPubKey string

	wgClient *wgctrl.Client

	assignPrefix netip.Prefix
	serverAddr   netip.Addr
	nextAddr     netip.Addr
	endAddr      netip.Addr

	peers      map[string]*vpnPeerState
	peersMutex sync.RWMutex

	lastPeerStates map[string]bool

	unsubscribe func()
}

type iptRule struct {
	table string
	chain string
	spec  []string
}

func (r iptRule) tableArgs() []string {
	if r.table != "" {
		return []string{"-t", r.table}
	}
	return nil
}

func NewVPN(cfg *config.Config, b bus.Bus, logger *slog.Logger) *VPNService {
	if logger == nil {
		logger = slog.Default()
	}
	return &VPNService{
		cfg:            cfg,
		bus:            b,
		log:            logger.With("component", "vpn"),
		ifaceName:      vpnIface,
		listenPort:     vpnPort,
		peers:          make(map[string]*vpnPeerState),
		lastPeerStates: make(map[string]bool),
	}
}

func (s *VPNService) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.started {
		return nil
	}

	if s.cfg.VPN.Assign == nil {
		s.log.Info("vpn service skipped", "reason", "no assignment configured")
		s.started = true
		return nil
	}

	prefix := *s.cfg.VPN.Assign
	s.assignPrefix = prefix

	startAddr, endAddr, err := vpnPoolBounds(prefix)
	if err != nil {
		return fmt.Errorf("vpn: %w", err)
	}
	s.serverAddr = startAddr
	s.nextAddr = startAddr.Next()
	s.endAddr = endAddr

	s.started = true
	s.ctx, s.cancel = context.WithCancel(ctx)

	if err := os.MkdirAll(vpnStateDir, 0700); err != nil {
		s.started = false
		return fmt.Errorf("vpn: mkdir: %w", err)
	}

	cl, err := wgctrl.New()
	if err != nil {
		s.started = false
		return fmt.Errorf("vpn: wgctrl: %w", err)
	}
	s.wgClient = cl

	if err := createWireGuardIface(s.ifaceName); err != nil {
		s.wgClient.Close()
		s.started = false
		return fmt.Errorf("vpn: create iface: %w", err)
	}

	if err := s.loadOrGenerateKey(); err != nil {
		s.cleanupIface()
		s.started = false
		return fmt.Errorf("vpn: key: %w", err)
	}

	if err := s.loadPeers(); err != nil {
		s.log.Warn("failed to load persisted peers", "error", err)
	}

	if err := s.configureDevice(); err != nil {
		s.cleanupIface()
		s.started = false
		return fmt.Errorf("vpn: configure: %w", err)
	}

	if err := assignInterfaceIP(s.ifaceName, prefix); err != nil {
		s.cleanupIface()
		s.started = false
		return fmt.Errorf("vpn: assign ip: %w", err)
	}

	if err := interfaceUp(s.ifaceName); err != nil {
		s.cleanupIface()
		s.started = false
		return fmt.Errorf("vpn: up: %w", err)
	}

	if err := s.setupNAT(); err != nil {
		s.log.Warn("nat setup failed (forwarding may not work)", "error", err)
	}

	s.restorePeers()

	s.announceRoute()

	if s.bus != nil {
		events, unsubscribe := s.bus.Subscribe(32)
		s.unsubscribe = unsubscribe
		go s.consumeEvents(events)
	}

	go s.monitorPeers()

	s.log.Info("vpn service started",
		"interface", s.ifaceName,
		"prefix", prefix.String(),
		"port", s.listenPort,
		"server_pubkey", s.serverPubKey,
	)
	return nil
}

func (s *VPNService) Stop(ctx context.Context) error {
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
	_ = s.removeNAT()
	_ = removeWireGuardIface(s.ifaceName)
	s.log.Info("vpn service stopped")
	return nil
}

func (s *VPNService) ServerPublicKey() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.serverPubKey
}

func (s *VPNService) GenerateClientConfig(name, endpoint string) (cfgText string, clientPrivKey string, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started {
		return "", "", errors.New("vpn service not started")
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return "", "", fmt.Errorf("generate client key: %w", err)
	}
	clientPrivKey = key.String()
	clientPubKey := key.PublicKey().String()

	addr, err := s.allocateIP()
	if err != nil {
		return "", "", fmt.Errorf("allocate ip: %w", err)
	}

	if err := s.addPeer(clientPubKey, addr); err != nil {
		return "", "", fmt.Errorf("add peer: %w", err)
	}

	s.peersMutex.Lock()
	s.peers[clientPubKey] = &vpnPeerState{
		Name:      name,
		PublicKey: clientPubKey,
		Address:   addr.String(),
		CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	s.peersMutex.Unlock()
	s.savePeers()

	if s.bus != nil {
		_ = s.bus.Publish(context.Background(), domain.PeerStateChanged{
			Peer: domain.Peer{
				Name:      name,
				Connected: false,
			},
		})
		if name != "" {
			dnsName := domain.EnsureTLD(name, s.cfg.Global.TLD)
			_ = s.bus.Publish(context.Background(), domain.DNSRecordUpserted{
				Record: domain.DNSRecord{
					Name: dnsName,
					Addr: addrPtr(addr),
				},
			})
		}
	}

	dnsAddrs := s.cfg.DHCP.DNS
	dnsStr := ""
	if len(dnsAddrs) > 0 {
		dnsStr = dnsAddrs[0].String()
	} else {
		dnsStr = s.serverAddr.String()
	}

	builder := new(strings.Builder)
	builder.WriteString("[Interface]\n")
	builder.WriteString(fmt.Sprintf("PrivateKey = %s\n", clientPrivKey))
	builder.WriteString(fmt.Sprintf("Address = %s/%d\n", addr.String(), s.assignPrefix.Bits()))
	builder.WriteString(fmt.Sprintf("DNS = %s\n", dnsStr))
	builder.WriteString("\n[Peer]\n")
	builder.WriteString(fmt.Sprintf("PublicKey = %s\n", s.serverPubKey))
	builder.WriteString(fmt.Sprintf("Endpoint = %s:%d\n", endpoint, s.listenPort))
	builder.WriteString("AllowedIPs = 0.0.0.0/0\n")
	builder.WriteString("PersistentKeepalive = 25\n")

	return builder.String(), clientPrivKey, nil
}

func (s *VPNService) RemovePeer(pubKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.started {
		return errors.New("vpn service not started")
	}

	if err := s.removePeerFromWG(pubKey); err != nil {
		return fmt.Errorf("remove peer: %w", err)
	}

	s.peersMutex.Lock()
	delete(s.peers, pubKey)
	s.peersMutex.Unlock()
	s.savePeers()

	return nil
}

func (s *VPNService) ListPeers() []domain.Peer {
	if s.wgClient == nil {
		return nil
	}

	dev, err := s.wgClient.Device(s.ifaceName)
	if err != nil {
		s.log.Warn("wg device failed", "error", err)
		return nil
	}

	peers := make([]domain.Peer, 0, len(dev.Peers))
	for _, p := range dev.Peers {
		pubKey := p.PublicKey.String()

		s.peersMutex.RLock()
		ps, exists := s.peers[pubKey]
		s.peersMutex.RUnlock()

		name := pubKey[:16] + "..."
		if exists && ps.Name != "" {
			name = ps.Name
		}

		endpoint := ""
		if p.Endpoint != nil {
			endpoint = p.Endpoint.String()
		}

		peers = append(peers, domain.Peer{
			Name:      name,
			Connected: !p.LastHandshakeTime.IsZero(),
			Endpoint:  endpoint,
			PublicKey: pubKey,
		})
	}

	return peers
}

func (s *VPNService) loadOrGenerateKey() error {
	keyPath := filepath.Join(vpnStateDir, vpnKeyFile)

	data, err := os.ReadFile(keyPath)
	if err == nil {
		privStr := strings.TrimSpace(string(data))
		if privStr != "" {
			key, err := wgtypes.ParseKey(privStr)
			if err != nil {
				return fmt.Errorf("parse private key: %w", err)
			}
			s.serverPubKey = key.PublicKey().String()

			if s.wgClient != nil {
				port := s.listenPort
				if err := s.wgClient.ConfigureDevice(s.ifaceName, wgtypes.Config{
					PrivateKey: &key,
					ListenPort: &port,
				}); err != nil {
					return fmt.Errorf("configure device: %w", err)
				}
			}
			s.log.Info("loaded existing vpn server key")
			return nil
		}
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read key file: %w", err)
	}

	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return fmt.Errorf("generate private key: %w", err)
	}
	pubStr := key.PublicKey().String()
	s.serverPubKey = pubStr

	if err := os.WriteFile(keyPath, []byte(key.String()+"\n"), 0600); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}

	if s.wgClient != nil {
		port := s.listenPort
		if err := s.wgClient.ConfigureDevice(s.ifaceName, wgtypes.Config{
			PrivateKey: &key,
			ListenPort: &port,
		}); err != nil {
			return fmt.Errorf("configure device: %w", err)
		}
	}

	s.log.Info("generated new vpn server key", "pubkey", pubStr)
	return nil
}

func (s *VPNService) configureDevice() error {
	if s.wgClient == nil {
		return errors.New("wgctrl client not initialized")
	}
	port := s.listenPort
	keyPath := filepath.Join(vpnStateDir, vpnKeyFile)
	data, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("read key: %w", err)
	}
	key, err := wgtypes.ParseKey(strings.TrimSpace(string(data)))
	if err != nil {
		return fmt.Errorf("parse key: %w", err)
	}
	if err := s.wgClient.ConfigureDevice(s.ifaceName, wgtypes.Config{
		PrivateKey: &key,
		ListenPort: &port,
	}); err != nil {
		return fmt.Errorf("configure device: %w", err)
	}
	return nil
}

func (s *VPNService) restorePeers() {
	s.peersMutex.RLock()
	defer s.peersMutex.RUnlock()

	if s.wgClient == nil {
		return
	}

	for pubKey, ps := range s.peers {
		_, err := netip.ParseAddr(ps.Address)
		if err != nil {
			s.log.Warn("invalid peer address in state", "peer", ps.Name, "address", ps.Address)
			continue
		}

		pk, err := wgtypes.ParseKey(pubKey)
		if err != nil {
			s.log.Warn("invalid peer public key", "peer", ps.Name, "error", err)
			continue
		}

		_, ipNet, err := net.ParseCIDR(ps.Address + "/32")
		if err != nil {
			continue
		}

		if err := s.wgClient.ConfigureDevice(s.ifaceName, wgtypes.Config{
			Peers: []wgtypes.PeerConfig{{
				PublicKey:  pk,
				AllowedIPs: []net.IPNet{*ipNet},
			}},
		}); err != nil {
			s.log.Warn("failed to restore peer", "name", ps.Name, "error", err)
		} else {
			s.log.Info("restored peer", "name", ps.Name, "address", ps.Address)
		}
	}
}

func (s *VPNService) allocateIP() (netip.Addr, error) {
	s.peersMutex.RLock()
	defer s.peersMutex.RUnlock()

	used := make(map[string]bool)
	for _, ps := range s.peers {
		used[ps.Address] = true
	}

	for addr := s.nextAddr; addr.IsValid() && addr.Compare(s.endAddr) <= 0; addr = addr.Next() {
		if !used[addr.String()] {
			s.nextAddr = addr.Next()
			return addr, nil
		}
	}

	return netip.Addr{}, errors.New("vpn address pool exhausted")
}

func (s *VPNService) addPeer(pubKey string, addr netip.Addr) error {
	if s.wgClient == nil {
		return errors.New("wgctrl client not initialized")
	}

	pk, err := wgtypes.ParseKey(pubKey)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	ipNet := net.IPNet{
		IP:   net.IP(addr.AsSlice()),
		Mask: net.CIDRMask(32, 32),
	}

	if err := s.wgClient.ConfigureDevice(s.ifaceName, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey:  pk,
			AllowedIPs: []net.IPNet{ipNet},
		}},
	}); err != nil {
		return fmt.Errorf("configure peer: %w", err)
	}

	s.log.Info("added vpn peer", "pubkey", pubKey[:16]+"...", "address", addr.String())
	return nil
}

func (s *VPNService) removePeerFromWG(pubKey string) error {
	if s.wgClient == nil {
		return errors.New("wgctrl client not initialized")
	}

	pk, err := wgtypes.ParseKey(pubKey)
	if err != nil {
		return fmt.Errorf("parse public key: %w", err)
	}

	if err := s.wgClient.ConfigureDevice(s.ifaceName, wgtypes.Config{
		Peers: []wgtypes.PeerConfig{{
			PublicKey: pk,
			Remove:    true,
		}},
	}); err != nil {
		return fmt.Errorf("remove peer: %w", err)
	}

	s.log.Info("removed vpn peer", "pubkey", pubKey[:16]+"...")
	return nil
}

func (s *VPNService) setupNAT() error {
	_ = exec.Command("sysctl", "-w", "net.ipv4.ip_forward=1").Run()

	prefix := s.assignPrefix.String()

	rules := []iptRule{
		{"nat", "POSTROUTING", []string{"-s", prefix, "-j", "MASQUERADE", "-m", "comment", "--comment", iptablesNAT}},
		{"", "FORWARD", []string{"-i", s.ifaceName, "-j", "ACCEPT", "-m", "comment", "--comment", iptablesFwdIn}},
		{"", "FORWARD", []string{"-o", s.ifaceName, "-j", "ACCEPT", "-m", "comment", "--comment", iptablesFwdOut}},
	}

	for _, rule := range rules {
		addArgs := rule.tableArgs()
		addArgs = append(addArgs, "-A", rule.chain)
		addArgs = append(addArgs, rule.spec...)

		out, err := exec.Command("iptables", addArgs...).CombinedOutput()
		if err != nil {
			if strings.Contains(string(out), "exists") {
				continue
			}
			return fmt.Errorf("iptables add: %w: %s", err, strings.TrimSpace(string(out)))
		}
	}

	return nil
}

func (s *VPNService) removeNAT() error {
	prefix := s.assignPrefix.String()

	rules := []iptRule{
		{"nat", "POSTROUTING", []string{"-s", prefix, "-j", "MASQUERADE", "-m", "comment", "--comment", iptablesNAT}},
		{"", "FORWARD", []string{"-i", s.ifaceName, "-j", "ACCEPT", "-m", "comment", "--comment", iptablesFwdIn}},
		{"", "FORWARD", []string{"-o", s.ifaceName, "-j", "ACCEPT", "-m", "comment", "--comment", iptablesFwdOut}},
	}

	var errs []error
	for _, rule := range rules {
		delArgs := rule.tableArgs()
		delArgs = append(delArgs, "-D", rule.chain)
		delArgs = append(delArgs, rule.spec...)

		out, err := exec.Command("iptables", delArgs...).CombinedOutput()
		if err != nil {
			if strings.Contains(string(out), "does not exist") || strings.Contains(string(out), "Bad rule") {
				continue
			}
			errs = append(errs, fmt.Errorf("iptables del: %w: %s", err, strings.TrimSpace(string(out))))
		}
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (s *VPNService) announceRoute() {
	if s.bus == nil {
		return
	}
	_ = s.bus.Publish(context.Background(), domain.RouteAnnounced{
		Route: domain.Route{
			Prefix:  s.assignPrefix,
			Gateway: &s.serverAddr,
		},
	})
	s.log.Info("announced vpn route", "prefix", s.assignPrefix.String())
}

func (s *VPNService) monitorPeers() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.checkPeerStates()
		}
	}
}

func (s *VPNService) checkPeerStates() {
	if s.wgClient == nil {
		return
	}

	dev, err := s.wgClient.Device(s.ifaceName)
	if err != nil {
		return
	}

	current := make(map[string]bool)
	for _, p := range dev.Peers {
		pubKey := p.PublicKey.String()
		current[pubKey] = !p.LastHandshakeTime.IsZero()
	}

	s.peersMutex.RLock()
	for pubKey, ps := range s.peers {
		wasConnected := s.lastPeerStates[pubKey]
		isConnected := current[pubKey]

		if wasConnected != isConnected {
			s.log.Info("vpn peer state changed",
				"name", ps.Name,
				"connected", isConnected,
			)
			if s.bus != nil {
				_ = s.bus.Publish(context.Background(), domain.PeerStateChanged{
					Peer: domain.Peer{
						Name:      ps.Name,
						Connected: isConnected,
					},
				})
				if isConnected && ps.Name != "" {
					addr, err := netip.ParseAddr(ps.Address)
					if err == nil {
						dnsName := domain.EnsureTLD(ps.Name, s.cfg.Global.TLD)
						_ = s.bus.Publish(context.Background(), domain.DNSRecordUpserted{
							Record: domain.DNSRecord{
								Name: dnsName,
								Addr: addrPtr(addr),
							},
						})
					}
				}
			}
		}
	}
	s.peersMutex.RUnlock()

	s.lastPeerStates = current
}

func (s *VPNService) consumeEvents(events <-chan bus.Event) {
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

func (s *VPNService) savePeers() {
	s.peersMutex.RLock()
	peers := make([]vpnPeerState, 0, len(s.peers))
	for _, ps := range s.peers {
		peers = append(peers, *ps)
	}
	s.peersMutex.RUnlock()

	data, err := json.Marshal(peers)
	if err != nil {
		s.log.Warn("marshal peers", "error", err)
		return
	}

	path := filepath.Join(vpnStateDir, vpnPeersFile)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		s.log.Warn("write peers tmp", "error", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		s.log.Warn("rename peers", "error", err)
	}
}

func (s *VPNService) loadPeers() error {
	path := filepath.Join(vpnStateDir, vpnPeersFile)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	var peers []vpnPeerState
	if err := json.Unmarshal(data, &peers); err != nil {
		return err
	}

	s.peersMutex.Lock()
	defer s.peersMutex.Unlock()

	for _, ps := range peers {
		if _, exists := s.peers[ps.PublicKey]; !exists {
			s.peers[ps.PublicKey] = &vpnPeerState{
				Name:      ps.Name,
				PublicKey: ps.PublicKey,
				Address:   ps.Address,
				CreatedAt: ps.CreatedAt,
			}
		}
	}

	s.log.Info("loaded persisted vpn peers", "count", len(peers))
	return nil
}

func (s *VPNService) cleanupIface() {
	_ = removeWireGuardIface(s.ifaceName)
}

func createWireGuardIface(name string) error {
	la := netlink.NewLinkAttrs()
	la.Name = name
	link := &netlink.GenericLink{
		LinkAttrs: la,
		LinkType:  "wireguard",
	}
	if err := netlink.LinkAdd(link); err != nil {
		if strings.Contains(err.Error(), "exists") {
			return nil
		}
		return fmt.Errorf("link add: %w", err)
	}
	return nil
}

func removeWireGuardIface(name string) error {
	link, err := netlink.LinkByName(name)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return nil
		}
		return err
	}
	return netlink.LinkDel(link)
}

func assignInterfaceIP(iface string, prefix netip.Prefix) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("link by name: %w", err)
	}

	addr, err := netlink.ParseAddr(prefix.String())
	if err != nil {
		return fmt.Errorf("parse addr: %w", err)
	}

	if err := netlink.AddrAdd(link, addr); err != nil {
		if strings.Contains(err.Error(), "exists") {
			return nil
		}
		return fmt.Errorf("addr add: %w", err)
	}
	return nil
}

func interfaceUp(iface string) error {
	link, err := netlink.LinkByName(iface)
	if err != nil {
		return fmt.Errorf("link by name: %w", err)
	}
	return netlink.LinkSetUp(link)
}

func vpnPoolBounds(prefix netip.Prefix) (netip.Addr, netip.Addr, error) {
	masked := prefix.Masked()
	start := masked.Addr()
	end, err := vpnPrefixEnd(masked)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, err
	}
	if start.Is4() && masked.Bits() < 31 {
		start = start.Next()
		end = end.Prev()
	}
	return start, end, nil
}

func vpnPrefixEnd(prefix netip.Prefix) (netip.Addr, error) {
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
