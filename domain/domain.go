package domain

import (
	"net/netip"
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
