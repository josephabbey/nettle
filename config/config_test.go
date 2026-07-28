package config

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseNettlefile(t *testing.T) {
	path := filepath.Join("..", "test", "Nettlefile")
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	defer f.Close()

	cfg, err := Parse(path, f)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("validate config: %v", err)
	}

	if got, want := cfg.Global.TLD, "ruins"; got != want {
		t.Fatalf("tld = %q, want %q", got, want)
	}
	if got, want := cfg.Global.HostsFile, "/etc/hosts"; got != want {
		t.Fatalf("hosts file = %q, want %q", got, want)
	}
	if got, want := cfg.DNS.Network, "udp"; got != want {
		t.Fatalf("dns network = %q, want %q", got, want)
	}
	if got, want := len(cfg.DNS.Upstreams), 2; got != want {
		t.Fatalf("dns upstream count = %d, want %d", got, want)
	}
	if got, want := len(cfg.Hosts), 2; got != want {
		t.Fatalf("host record count = %d, want %d", got, want)
	}
	if got, want := len(cfg.Glue), 1; got != want {
		t.Fatalf("glue count = %d, want %d", got, want)
	}
	if cfg.DHCP.Main.Interface != "eth0" {
		t.Fatalf("dhcp main interface = %q, want eth0", cfg.DHCP.Main.Interface)
	}
	if cfg.DHCP.Guest == nil || cfg.DHCP.Guest.Interface != "wlan1" {
		t.Fatalf("dhcp guest interface = %#v, want wlan1", cfg.DHCP.Guest)
	}
	if cfg.VPN.Assign == nil || cfg.VPN.Assign.String() != "192.168.128.0/24" {
		t.Fatalf("vpn assign = %#v, want 192.168.128.0/24", cfg.VPN.Assign)
	}
}

func TestValidateDetectsOverlap(t *testing.T) {
	mainPrefix, err := netip.ParsePrefix("192.168.0.0/24")
	if err != nil {
		t.Fatalf("parse main prefix: %v", err)
	}
	guestPrefix, err := netip.ParsePrefix("192.168.0.128/25")
	if err != nil {
		t.Fatalf("parse guest prefix: %v", err)
	}

	cfg := &Config{
		Global: GlobalConfig{TLD: "ruins"},
		DHCP: DHCPConfig{
			Main:  Assignment{Prefix: &mainPrefix},
			Guest: &Assignment{Prefix: &guestPrefix},
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("validate overlap = nil, want error")
	}
}

func TestParseRejectsUnsupportedDirective(t *testing.T) {
	const input = `{
		tld ruins
		unknown nope
	}`
	cfg, err := Parse("test", strings.NewReader(input))
	if err == nil {
		t.Fatalf("parse = %#v, want error", cfg)
	}
}
