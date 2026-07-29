package domain

import (
	"net/netip"
	"strings"
	"time"
)

type DNSRecord struct {
	Name  string
	Addr  *netip.Addr
	CNAME string
}

type Lease struct {
	Hostname     string
	HardwareAddr string
	Address      netip.Addr
	Interface    string
	LeaseUntil   time.Time
}

type Route struct {
	Prefix    netip.Prefix
	Gateway   *netip.Addr
	Interface string
}

type Peer struct {
	Name      string
	Connected bool
	Endpoint  string
	PublicKey string
}

type DNSRecordUpserted struct {
	Record DNSRecord
}

type DHCPLeaseAssigned struct {
	Lease Lease
}

type RouteAnnounced struct {
	Route Route
}

type PeerStateChanged struct {
	Peer Peer
}

type StaticHost struct {
	Hostname     string
	HardwareAddr string
	Address      netip.Addr
}

type StaticHostUpserted struct {
	StaticHost StaticHost
}

func EnsureTLD(name, tld string) string {
	if tld == "" {
		return name
	}
	if !strings.Contains(name, ".") {
		return name + "." + tld
	}
	return name
}
