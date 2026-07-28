package config

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/josephabbey/conffile"
)

const (
	defaultHostsFile  = "/etc/hosts"
	defaultEthersFile = "/etc/ethers"
	defaultDNSServer  = "udp"
	defaultDNSPort    = 53
	defaultWebAddr    = "127.0.0.1:80"
	defaultLogLevel   = "info"
	defaultLogFormat  = "text"
	defaultMainLease  = 6 * time.Hour
	defaultGuestLease = time.Hour
)

type LoggingConfig struct {
	Level  string
	Format string
}

type GlobalConfig struct {
	TLD        string
	HostsFile  string
	EthersFile string
}

type AddressRange struct {
	Start netip.Addr
	End   netip.Addr
}

type Assignment struct {
	Prefix    *netip.Prefix
	Range     *AddressRange
	Interface string
	Lease     time.Duration
}

func (a Assignment) Bounds() (netip.Addr, netip.Addr, bool) {
	switch {
	case a.Prefix != nil:
		start, end, err := prefixInterval(*a.Prefix)
		if err != nil {
			return netip.Addr{}, netip.Addr{}, false
		}
		return bigIntToAddr(start, a.Prefix.Addr().Is6()), bigIntToAddr(end, a.Prefix.Addr().Is6()), true
	case a.Range != nil:
		return a.Range.Start, a.Range.End, true
	default:
		return netip.Addr{}, netip.Addr{}, false
	}
}

func (a Assignment) IsConfigured() bool {
	return a.Prefix != nil || a.Range != nil
}

type DHCPConfig struct {
	NTP     *netip.Addr
	Gateway *netip.Addr
	DNS     []netip.Addr
	Main    Assignment
	Guest   *Assignment
}

type DNSConfig struct {
	Port               int
	Network            string
	Upstreams          []netip.Addr
	RecursiveUpstreams map[string]netip.Addr
	Blocked            []string
}

type WebConfig struct {
	Addr string
}

type VPNConfig struct {
	Assign *netip.Prefix
}

type ConnectConfig struct {
	Target string
	NoDNS  bool
}

type GlueConfig struct {
	Address     string
	Connections []ConnectConfig
}

type HostRecord struct {
	Names []string
	IP    *netip.Addr
	CNAME string
}

type Config struct {
	Global  GlobalConfig
	Logging LoggingConfig
	DHCP    DHCPConfig
	DNS     DNSConfig
	Web     WebConfig
	VPN     VPNConfig
	Glue    []GlueConfig
	Hosts   []HostRecord
}

type allocationInterval struct {
	name  string
	start big.Int
	end   big.Int
}

func defaultConfig() Config {
	return Config{
		Global: GlobalConfig{
			HostsFile:  defaultHostsFile,
			EthersFile: defaultEthersFile,
		},
		Logging: LoggingConfig{
			Level:  defaultLogLevel,
			Format: defaultLogFormat,
		},
		DNS: DNSConfig{
			Port:               defaultDNSPort,
			Network:            defaultDNSServer,
			RecursiveUpstreams: map[string]netip.Addr{},
		},
		Web: WebConfig{
			Addr: defaultWebAddr,
		},
	}
}

func Parse(path string, r io.Reader) (*Config, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("%s: read config: %w", path, err)
	}

	ast, err := conffile.Parse(string(data))
	if err != nil {
		return nil, fmt.Errorf("%s: parse config: %w", path, err)
	}

	cfg := defaultConfig()

	if err := parseStatements(path, &cfg, ast.Global.Statements); err != nil {
		return nil, err
	}
	for _, matcher := range ast.Matchers {
		if err := parseMatcher(path, &cfg, matcher); err != nil {
			return nil, err
		}
	}

	return &cfg, nil
}

func parseStatements(path string, cfg *Config, stmts []conffile.Statement) error {
	for _, stmt := range stmts {
		switch stmt.Key {
		case "tld":
			value, err := requireSingleValue(path, stmt)
			if err != nil {
				return err
			}
			cfg.Global.TLD = value
		case "hosts":
			value, err := requireSingleValue(path, stmt)
			if err != nil {
				return err
			}
			cfg.Global.HostsFile = value
		case "ethers":
			value, err := requireSingleValue(path, stmt)
			if err != nil {
				return err
			}
			cfg.Global.EthersFile = value
		case "log":
			if err := parseLogging(path, &cfg.Logging, stmt); err != nil {
				return err
			}
		case "dhcp":
			if stmt.Block == nil {
				return directiveError(path, "dhcp", "expected block")
			}
			if err := parseDHCPBlock(path, &cfg.DHCP, stmt.Block.Statements); err != nil {
				return err
			}
		case "dns":
			if stmt.Block == nil {
				return directiveError(path, "dns", "expected block")
			}
			if err := parseDNSBlock(path, &cfg.DNS, stmt.Block.Statements); err != nil {
				return err
			}
		case "web":
			if err := parseWeb(path, &cfg.Web, stmt); err != nil {
				return err
			}
		case "vpn":
			if stmt.Block == nil {
				return directiveError(path, "vpn", "expected block")
			}
			if err := parseVPNBlock(path, &cfg.VPN, stmt.Block.Statements); err != nil {
				return err
			}
		case "glue":
			glue, err := parseGlue(path, stmt)
			if err != nil {
				return err
			}
			cfg.Glue = append(cfg.Glue, glue)
		default:
			return directiveError(path, stmt.Key, "unsupported top-level directive")
		}
	}
	return nil
}

func parseMatcher(path string, cfg *Config, matcher conffile.Matcher) error {
	record := HostRecord{Names: append([]string(nil), matcher.Patterns...)}
	for _, stmt := range matcher.Block.Statements {
		switch stmt.Key {
		case "ip":
			value, err := requireSingleValue(path, stmt)
			if err != nil {
				return err
			}
			addr, err := parseAddr(value)
			if err != nil {
				return fmt.Errorf("%s: host %s: %w", path, stmt.Key, err)
			}
			record.IP = &addr
		case "cname":
			value, err := requireSingleValue(path, stmt)
			if err != nil {
				return err
			}
			record.CNAME = value
		default:
			return directiveError(path, stmt.Key, "unsupported host directive")
		}
	}
	cfg.Hosts = append(cfg.Hosts, record)
	return nil
}

func parseLogging(path string, cfg *LoggingConfig, stmt conffile.Statement) error {
	if stmt.Block != nil {
		for _, nested := range stmt.Block.Statements {
			switch nested.Key {
			case "level":
				value, err := requireSingleValue(path, nested)
				if err != nil {
					return err
				}
				cfg.Level = value
			case "format":
				value, err := requireSingleValue(path, nested)
				if err != nil {
					return err
				}
				cfg.Format = value
			default:
				return directiveError(path, nested.Key, "unsupported log directive")
			}
		}
		return nil
	}

	fields, err := requiredFields(path, stmt, 1, 2)
	if err != nil {
		return err
	}
	switch len(fields) {
	case 1:
		cfg.Level = fields[0]
	case 2:
		cfg.Level = fields[0]
		cfg.Format = fields[1]
	}
	return nil
}

func parseDHCPBlock(path string, cfg *DHCPConfig, stmts []conffile.Statement) error {
	for _, stmt := range stmts {
		switch stmt.Key {
		case "ntp":
			value, err := requireSingleValue(path, stmt)
			if err != nil {
				return err
			}
			addr, err := parseAddr(value)
			if err != nil {
				return fmt.Errorf("%s: dhcp ntp: %w", path, err)
			}
			cfg.NTP = &addr
		case "gateway":
			value, err := requireSingleValue(path, stmt)
			if err != nil {
				return err
			}
			addr, err := parseAddr(value)
			if err != nil {
				return fmt.Errorf("%s: dhcp gateway: %w", path, err)
			}
			cfg.Gateway = &addr
		case "dns":
			fields := fieldsOf(stmt.Value)
			if len(fields) == 0 {
				return directiveError(path, "dns", "expected at least one address")
			}
			for _, raw := range fields {
				addr, err := parseAddr(raw)
				if err != nil {
					return fmt.Errorf("%s: dhcp dns: %w", path, err)
				}
				cfg.DNS = append(cfg.DNS, addr)
			}
		case "lease":
			value, err := requireSingleValue(path, stmt)
			if err != nil {
				return err
			}
			dur, err := time.ParseDuration(value)
			if err != nil {
				return fmt.Errorf("%s: dhcp lease: invalid duration %q: %w", path, value, err)
			}
			cfg.Main.Lease = dur
		case "assign":
			assign, err := parseAssignment(path, stmt)
			if err != nil {
				return err
			}
			cfg.Main.Prefix = assign.Prefix
			cfg.Main.Range = assign.Range
		case "intf":
			value, err := requireSingleValue(path, stmt)
			if err != nil {
				return err
			}
			cfg.Main.Interface = value
		case "guest":
			if stmt.Block == nil {
				return directiveError(path, "guest", "expected block")
			}
			guest := Assignment{Lease: defaultGuestLease}
			if err := parseAssignmentBlock(path, &guest, stmt.Block.Statements); err != nil {
				return err
			}
			cfg.Guest = &guest
		default:
			return directiveError(path, stmt.Key, "unsupported dhcp directive")
		}
	}
	if cfg.Main.Lease == 0 && (cfg.Main.Prefix != nil || cfg.Main.Range != nil) {
		cfg.Main.Lease = defaultMainLease
	}
	return nil
}

func parseAssignmentBlock(path string, cfg *Assignment, stmts []conffile.Statement) error {
	for _, stmt := range stmts {
		switch stmt.Key {
		case "lease":
			value, err := requireSingleValue(path, stmt)
			if err != nil {
				return err
			}
			dur, err := time.ParseDuration(value)
			if err != nil {
				return fmt.Errorf("%s: guest lease: invalid duration %q: %w", path, value, err)
			}
			cfg.Lease = dur
		case "assign":
			assign, err := parseAssignment(path, stmt)
			if err != nil {
				return err
			}
			cfg.Prefix = assign.Prefix
			cfg.Range = assign.Range
		case "intf":
			value, err := requireSingleValue(path, stmt)
			if err != nil {
				return err
			}
			cfg.Interface = value
		default:
			return directiveError(path, stmt.Key, "unsupported guest directive")
		}
	}
	return nil
}

func parseAssignment(path string, stmt conffile.Statement) (Assignment, error) {
	fields := fieldsOf(stmt.Value)
	if len(fields) == 0 {
		return Assignment{}, directiveError(path, stmt.Key, "expected assignment")
	}
	if fields[0] == "range" {
		switch len(fields) {
		case 2:
			prefix, err := netip.ParsePrefix(fields[1])
			if err != nil {
				return Assignment{}, fmt.Errorf("%s: assign range prefix %q: %w", path, fields[1], err)
			}
			prefix = prefix.Masked()
			return Assignment{Prefix: &prefix}, nil
		case 3:
			start, err := parseAddr(fields[1])
			if err != nil {
				return Assignment{}, fmt.Errorf("%s: assign range: %w", path, err)
			}
			end, err := parseAddr(fields[2])
			if err != nil {
				return Assignment{}, fmt.Errorf("%s: assign range: %w", path, err)
			}
			return Assignment{Range: &AddressRange{Start: start, End: end}}, nil
		default:
			return Assignment{}, directiveError(path, stmt.Key, "range requires a prefix or start and end address")
		}
	}

	if len(fields) != 1 {
		return Assignment{}, directiveError(path, stmt.Key, "expected a single CIDR or 'range start end'")
	}
	prefix, err := netip.ParsePrefix(fields[0])
	if err != nil {
		return Assignment{}, fmt.Errorf("%s: assign prefix %q: %w", path, fields[0], err)
	}
	prefix = prefix.Masked()
	return Assignment{Prefix: &prefix}, nil
}

func parseDNSBlock(path string, cfg *DNSConfig, stmts []conffile.Statement) error {
	for _, stmt := range stmts {
		switch stmt.Key {
		case "port":
			value, err := requireSingleValue(path, stmt)
			if err != nil {
				return err
			}
			port, err := parsePort(value)
			if err != nil {
				return fmt.Errorf("%s: dns port: %w", path, err)
			}
			cfg.Port = port
		case "net":
			value, err := requireSingleValue(path, stmt)
			if err != nil {
				return err
			}
			cfg.Network = value
		case "upstream":
			fields := fieldsOf(stmt.Value)
			switch len(fields) {
			case 1:
				addr, err := parseAddr(fields[0])
				if err != nil {
					return fmt.Errorf("%s: dns upstream: %w", path, err)
				}
				cfg.Upstreams = append(cfg.Upstreams, addr)
			case 2:
				addr, err := parseAddr(fields[1])
				if err != nil {
					return fmt.Errorf("%s: dns upstream %q: %w", path, fields[0], err)
				}
				if cfg.RecursiveUpstreams == nil {
					cfg.RecursiveUpstreams = map[string]netip.Addr{}
				}
				cfg.RecursiveUpstreams[fields[0]] = addr
			default:
				return directiveError(path, stmt.Key, "expected upstream address or zone plus address")
			}
		case "block":
			fields := fieldsOf(stmt.Value)
			if len(fields) > 0 {
				cfg.Blocked = append(cfg.Blocked, fields...)
				continue
			}
			if stmt.Block == nil {
				return directiveError(path, "block", "expected value or nested block")
			}
			for _, nested := range stmt.Block.Statements {
				if nested.Key != "" {
					if val := strings.TrimSpace(valueString(nested.Value)); val != "" {
						cfg.Blocked = append(cfg.Blocked, nested.Key+" "+val)
					} else {
						cfg.Blocked = append(cfg.Blocked, nested.Key)
					}
				}
			}
		default:
			return directiveError(path, stmt.Key, "unsupported dns directive")
		}
	}
	return nil
}

func parseWeb(path string, cfg *WebConfig, stmt conffile.Statement) error {
	if stmt.Block != nil {
		for _, nested := range stmt.Block.Statements {
			switch nested.Key {
			case "addr", "address", "listen":
				value, err := requireSingleValue(path, nested)
				if err != nil {
					return err
				}
				cfg.Addr = value
			default:
				return directiveError(path, nested.Key, "unsupported web directive")
			}
		}
		return nil
	}

	value, err := requireSingleValue(path, stmt)
	if err != nil {
		return err
	}
	cfg.Addr = value
	return nil
}

func parseVPNBlock(path string, cfg *VPNConfig, stmts []conffile.Statement) error {
	for _, stmt := range stmts {
		switch stmt.Key {
		case "assign":
			value, err := requireSingleValue(path, stmt)
			if err != nil {
				return err
			}
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				return fmt.Errorf("%s: vpn assign %q: %w", path, value, err)
			}
			prefix = prefix.Masked()
			cfg.Assign = &prefix
		default:
			return directiveError(path, stmt.Key, "unsupported vpn directive")
		}
	}
	return nil
}

func parseGlue(path string, stmt conffile.Statement) (GlueConfig, error) {
	address, err := requireSingleValue(path, stmt)
	if err != nil {
		return GlueConfig{}, err
	}
	glue := GlueConfig{Address: address}
	if stmt.Block == nil {
		return glue, nil
	}
	for _, nested := range stmt.Block.Statements {
		switch nested.Key {
		case "connect":
			connect, err := parseConnect(path, nested)
			if err != nil {
				return GlueConfig{}, err
			}
			glue.Connections = append(glue.Connections, connect)
		default:
			return GlueConfig{}, directiveError(path, nested.Key, "unsupported glue directive")
		}
	}
	return glue, nil
}

func parseConnect(path string, stmt conffile.Statement) (ConnectConfig, error) {
	target, err := requireSingleValue(path, stmt)
	if err != nil {
		return ConnectConfig{}, err
	}
	connect := ConnectConfig{Target: target}
	if stmt.Block == nil {
		return connect, nil
	}
	for _, nested := range stmt.Block.Statements {
		switch nested.Key {
		case "nodns":
			connect.NoDNS = true
		default:
			return ConnectConfig{}, directiveError(path, nested.Key, "unsupported connect directive")
		}
	}
	return connect, nil
}

func (c *Config) Validate() error {
	var errs []error

	if strings.TrimSpace(c.Global.TLD) == "" {
		errs = append(errs, errors.New("global tld is required"))
	}
	if c.DNS.Port < 0 || c.DNS.Port > 65535 {
		errs = append(errs, fmt.Errorf("dns port %d out of range", c.DNS.Port))
	}
	if c.DNS.Network != "" {
		switch c.DNS.Network {
		case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6":
		default:
			errs = append(errs, fmt.Errorf("dns network %q is not supported", c.DNS.Network))
		}
	}
	if err := validateLogging(c.Logging); err != nil {
		errs = append(errs, err)
	}
	if strings.TrimSpace(c.Web.Addr) == "" {
		c.Web.Addr = defaultWebAddr
	}
	if err := validateWeb(c.Web); err != nil {
		errs = append(errs, err)
	}
	if c.DHCP.hasConfig() && !c.DHCP.Main.IsConfigured() {
		errs = append(errs, errors.New("dhcp main assignment is required when dhcp is configured"))
	}
	if c.DHCP.Guest != nil && !c.DHCP.Guest.IsConfigured() {
		errs = append(errs, errors.New("dhcp guest assignment is required when guest block is present"))
	}
	if err := validateAssignment("dhcp main", c.DHCP.Main); err != nil {
		errs = append(errs, err)
	}
	if c.DHCP.Guest != nil {
		if err := validateAssignment("dhcp guest", *c.DHCP.Guest); err != nil {
			errs = append(errs, err)
		}
	}
	if c.VPN.Assign != nil {
		if err := validatePrefix("vpn assign", *c.VPN.Assign); err != nil {
			errs = append(errs, err)
		}
	}
	for i, host := range c.Hosts {
		if len(host.Names) == 0 {
			errs = append(errs, fmt.Errorf("host record %d has no names", i))
			continue
		}
		if host.IP == nil && host.CNAME == "" {
			errs = append(errs, fmt.Errorf("host record %q has no ip or cname", host.Names[0]))
		}
		if host.IP != nil && host.CNAME != "" {
			errs = append(errs, fmt.Errorf("host record %q cannot set both ip and cname", host.Names[0]))
		}
	}
	for zone, addr := range c.DNS.RecursiveUpstreams {
		if zone == "" {
			errs = append(errs, errors.New("dns recursive upstream has empty zone"))
		}
		if !addr.IsValid() {
			errs = append(errs, fmt.Errorf("dns recursive upstream %q has invalid address", zone))
		}
	}
	for i, glue := range c.Glue {
		if strings.TrimSpace(glue.Address) == "" {
			errs = append(errs, fmt.Errorf("glue %d has no address", i))
		}
		if len(glue.Connections) == 0 {
			errs = append(errs, fmt.Errorf("glue %q has no connections", glue.Address))
		}
		for j, conn := range glue.Connections {
			if strings.TrimSpace(conn.Target) == "" {
				errs = append(errs, fmt.Errorf("glue %q connection %d has no target", glue.Address, j))
			}
		}
	}
	if overlapErr := validateAllocationOverlap(c); overlapErr != nil {
		errs = append(errs, overlapErr)
	}

	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func (c DHCPConfig) hasConfig() bool {
	return c.NTP != nil || c.Gateway != nil || len(c.DNS) > 0 || c.Main.IsConfigured() || c.Guest != nil
}

func validateAssignment(name string, a Assignment) error {
	switch {
	case a.Prefix != nil && a.Range != nil:
		return fmt.Errorf("%s cannot set both prefix and range", name)
	case a.Prefix == nil && a.Range == nil:
		return nil
	case a.Prefix != nil:
		return validatePrefix(name, *a.Prefix)
	case a.Range != nil:
		return validateRange(name, *a.Range)
	default:
		return nil
	}
}

func validateLogging(cfg LoggingConfig) error {
	var level slog.LevelVar
	if cfg.Level == "" {
		cfg.Level = defaultLogLevel
	}
	if err := level.UnmarshalText([]byte(cfg.Level)); err != nil {
		return fmt.Errorf("log level %q is invalid: %w", cfg.Level, err)
	}
	switch cfg.Format {
	case "", "text", "json":
		return nil
	default:
		return fmt.Errorf("log format %q is not supported", cfg.Format)
	}
}

func validateWeb(cfg WebConfig) error {
	if strings.TrimSpace(cfg.Addr) == "" {
		return errors.New("web addr is required")
	}
	host, port, err := net.SplitHostPort(cfg.Addr)
	if err != nil {
		return fmt.Errorf("web addr %q is invalid: %w", cfg.Addr, err)
	}
	if port == "" {
		return fmt.Errorf("web addr %q is invalid: missing port", cfg.Addr)
	}
	if host == "" && !strings.HasPrefix(cfg.Addr, ":") {
		return fmt.Errorf("web addr %q is invalid", cfg.Addr)
	}
	return nil
}

func validatePrefix(name string, prefix netip.Prefix) error {
	if !prefix.IsValid() {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func validateRange(name string, r AddressRange) error {
	if !r.Start.IsValid() || !r.End.IsValid() {
		return fmt.Errorf("%s contains invalid addresses", name)
	}
	if r.Start.Compare(r.End) > 0 {
		return fmt.Errorf("%s start %s is after end %s", name, r.Start, r.End)
	}
	if r.Start.Is4() != r.End.Is4() {
		return fmt.Errorf("%s crosses IP families", name)
	}
	return nil
}

func validateAllocationOverlap(c *Config) error {
	var intervals []allocationInterval

	addPrefix := func(name string, prefix *netip.Prefix) error {
		if prefix == nil {
			return nil
		}
		start, end, err := prefixInterval(*prefix)
		if err != nil {
			return err
		}
		intervals = append(intervals, allocationInterval{name: name, start: start, end: end})
		return nil
	}
	addRange := func(name string, r *AddressRange) error {
		if r == nil {
			return nil
		}
		start, end, err := addressInterval(*r)
		if err != nil {
			return err
		}
		intervals = append(intervals, allocationInterval{name: name, start: start, end: end})
		return nil
	}

	if err := addPrefix("dhcp main", c.DHCP.Main.Prefix); err != nil {
		return err
	}
	if err := addRange("dhcp main", c.DHCP.Main.Range); err != nil {
		return err
	}
	if c.DHCP.Guest != nil {
		if err := addPrefix("dhcp guest", c.DHCP.Guest.Prefix); err != nil {
			return err
		}
		if err := addRange("dhcp guest", c.DHCP.Guest.Range); err != nil {
			return err
		}
	}
	if err := addPrefix("vpn", c.VPN.Assign); err != nil {
		return err
	}

	for i := 0; i < len(intervals); i++ {
		for j := i + 1; j < len(intervals); j++ {
			if intervalsOverlap(intervals[i], intervals[j]) {
				return fmt.Errorf("%s overlaps with %s", intervals[i].name, intervals[j].name)
			}
		}
	}
	return nil
}

func intervalsOverlap(a, b allocationInterval) bool {
	if a.end.Cmp(&b.start) < 0 || b.end.Cmp(&a.start) < 0 {
		return false
	}
	return true
}

func prefixInterval(prefix netip.Prefix) (big.Int, big.Int, error) {
	masked := prefix.Masked()
	start, err := addrToBig(masked.Addr())
	if err != nil {
		return big.Int{}, big.Int{}, err
	}
	bits := 32
	if masked.Addr().Is6() {
		bits = 128
	}
	hostBits := bits - masked.Bits()
	if hostBits < 0 {
		return big.Int{}, big.Int{}, fmt.Errorf("invalid prefix %s", prefix)
	}
	var size big.Int
	size.Lsh(big.NewInt(1), uint(hostBits))
	var end big.Int
	end.Add(&start, new(big.Int).Sub(&size, big.NewInt(1)))
	return start, end, nil
}

func addressInterval(r AddressRange) (big.Int, big.Int, error) {
	start, err := addrToBig(r.Start)
	if err != nil {
		return big.Int{}, big.Int{}, err
	}
	end, err := addrToBig(r.End)
	if err != nil {
		return big.Int{}, big.Int{}, err
	}
	return start, end, nil
}

func addrToBig(addr netip.Addr) (big.Int, error) {
	if !addr.IsValid() {
		return big.Int{}, fmt.Errorf("invalid address")
	}
	var bytes []byte
	switch {
	case addr.Is4():
		a := addr.As4()
		bytes = a[:]
	case addr.Is6():
		a := addr.As16()
		bytes = a[:]
	default:
		return big.Int{}, fmt.Errorf("unsupported address family")
	}
	var n big.Int
	n.SetBytes(bytes)
	return n, nil
}

func bigIntToAddr(n big.Int, ipv6 bool) netip.Addr {
	if ipv6 {
		var b [16]byte
		raw := n.Bytes()
		copy(b[16-len(raw):], raw)
		return netip.AddrFrom16(b)
	}
	var b [4]byte
	raw := n.Bytes()
	copy(b[4-len(raw):], raw)
	return netip.AddrFrom4(b)
}

func parseAddr(raw string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(strings.TrimSpace(raw))
	if err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}

func parsePort(raw string) (int, error) {
	var port int
	if _, err := fmt.Sscanf(raw, "%d", &port); err != nil {
		return 0, fmt.Errorf("invalid port %q", raw)
	}
	if port < 1 || port > 65535 {
		return 0, fmt.Errorf("port %d out of range", port)
	}
	return port, nil
}

func fieldsOf(value *string) []string {
	if value == nil {
		return nil
	}
	return strings.Fields(*value)
}

func valueString(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func requireSingleValue(path string, stmt conffile.Statement) (string, error) {
	fields := fieldsOf(stmt.Value)
	if len(fields) != 1 {
		return "", directiveError(path, stmt.Key, "expected one value")
	}
	return fields[0], nil
}

func requiredFields(path string, stmt conffile.Statement, min, max int) ([]string, error) {
	fields := fieldsOf(stmt.Value)
	if len(fields) < min || len(fields) > max {
		return nil, directiveError(path, stmt.Key, fmt.Sprintf("expected %d-%d fields", min, max))
	}
	return fields, nil
}

func directiveError(path, directive, msg string) error {
	return fmt.Errorf("%s: %s: %s", path, directive, msg)
}
