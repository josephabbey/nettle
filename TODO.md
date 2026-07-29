# Nettle Implementation Status

## Config (`config/`)

- [x] Parse Nettlefile via `conffile` library
- [x] Global: `tld`, `hosts`, `ethers`
- [x] Logging: `level`, `format`
- [x] DHCP: main + guest pools, `ntp`, `gateway`, `dns`, `lease`, `assign` (prefix/range), `intf`
- [x] DNS: `port`, `net`, `upstream`, recursive upstreams per zone, `block` (domains + lists)
- [x] Web: `listen`/inline address
- [x] VPN: `assign` prefix
- [x] Glue/Connect: address, connection targets, `nodns` flag
- [x] Host matchers: `ip`, `cname`, wildcard names
- [x] Validation: overlap detection, range checks, port/address validation
- [x] Hosts file (`/etc/hosts`) parser
- [x] Ethers file (`/etc/ethers`) parser
- [x] Static host derivation from hosts + ethers
- [x] Tests for parse, overlap detection, unsupported directives

## DNS Service (`services/dns.go`)

- [x] Recursive DNS server using `miekg/dns`
- [x] Serves A, AAAA, CNAME records from local store
- [x] Upstream forwarding (general + per-zone recursive)
- [x] Domain blocklist (exact + wildcard suffixes)
- [x] Bus subscription for `DNSRecordUpserted` events
- [x] Wildcard record matching
- [x] NS record serving for connected Nettle instances
- [x] Dynamic upstream registration via `AddUpstream` / `RemoveUpstream`
- [x] NS queries delegated to dynamic upstream zones

## DHCP Service (`services/dhcp.go`)

- [x] DHCPv4 server using `insomniacslk/dhcp`
- [x] Main + guest pool support (different interfaces/ranges)
- [x] Static lease allocation from ethers/hosts
- [x] Dynamic address allocation with round-robin
- [x] Lease expiry + periodic cleanup
- [x] DNS record publishing via bus on assignment
- [x] DHCP lease assigned event publishing
- [x] Classless static route serving (for VPN/Connect routes)
- [x] Gateway, NTP, DNS server options
- [x] Lease persistence to disk
- [ ] VPN client lease management (roaming between networks/WiFi/VPN)
  - VPN publishes DNS records on connect/disconnect — IP follows the device

## VPN Service (`services/vpn.go`)

- [x] WireGuard server — interface management, key generation, NAT
- [x] WireGuard interface management via `netlink` + `wgctrl`
- [x] Server key generation/persistence (`/var/lib/nettle/vpn/`)
- [x] Client key/configuration generation (wg-quick format)
- [x] Peer management (add/remove/list) with IPAM
- [x] LAN/WAN access via iptables MASQUERADE + FORWARD rules
- [x] Route announcement via bus for DHCP to serve
- [x] Peer connection state monitoring + `PeerStateChanged` bus events
- [x] Peer state persistence to disk
- [x] DNS record publishing on peer connect for roaming support

## Connect Service (`services/connect.go`)

- [x] WireGuard tunnel management per connection target
- [x] Glue key generation/persistence per address (`/var/lib/nettle/connect/`)
- [x] Remote peer configuration (public key, endpoint, prefix) via `SetRemotePeer`
- [x] Static route setup across LANs via netlink
- [x] Route announcement via bus for DHCP
- [x] Dynamic DNS upstream registration via `DNSService.AddUpstream`
- [x] DNS record announcement for connected instances
- [x] Tunnel list/status API
- [ ] Handshake/pairing protocol (QR code exchange)
- [ ] IP range collision detection during handshake
- [ ] Cross-LAN device accessibility via DNS forwarding — **partial** (upstream works, forward zones pending)

## Web Service (`services/web.go`)

- [x] HTTP server with embedded assets
- [x] REST API: `/api/state`, `/api/leases`, `/api/dns-records`, `/api/static-hosts`
- [x] REST API: `/api/vpn/peers`, `/api/vpn/generate`
- [x] REST API: `/api/connect/tunnels`, `/api/connect/pair`
- [x] REST API: `/api/network` (aggregated graph data)
- [x] Server-Sent Events (SSE) live feed at `/events`
- [x] Consumes bus events: leases, DNS records, static hosts
- [x] Health check endpoint (`/healthz`)

### Web UI (`services/webui/`)

- [x] Dashboard with summary cards (leases, DNS records, static IPs, focus counts)
- [x] Live leases table with filter
- [x] Live DNS records table with filter
- [x] Static IPs table with filter
- [x] Real-time updates via SSE
- [x] Dark theme CSS
- [x] VPN config generation form + config download button
- [x] VPN peer table (name, status dot, endpoint, remove button)
- [x] Connect pairing form (target, endpoint, public key, prefix)
- [x] Connect tunnel table with status
- [x] Network map SVG graph (leases, VPN peers, Connect tunnels)

## Event Bus (`bus/`)

- [x] Pub/sub hub with generics-free `Event any` interface
- [x] `Subscribe` with buffer size + unsubscribe
- [x] `Publish` with context cancellation
- [x] Graceful `Close`

## Domain Types (`domain/`)

- [x] `DNSRecord`, `Lease`, `Route`, `Peer` (with `PublicKey`), `StaticHost`
- [x] Event wrappers: `DNSRecordUpserted`, `DHCPLeaseAssigned`, `RouteAnnounced`, `PeerStateChanged`, `StaticHostUpserted`
- [x] `EnsureTLD` helper

## Logging (`logging/`)

- [x] Text and JSON format handlers
- [x] Level configuration
- [x] Component logger helper
- [x] Tests

## Infrastructure

- [x] `main.go` wiring all services (DNS → Connect → Web)
- [x] Graceful shutdown (SIGINT/SIGTERM)
- [x] Dockerfile with iptables + WireGuard deps
- [x] docker-compose with `NET_ADMIN` + tun device + state volume
- [x] GitHub Actions workflow (Docker publish)
- [x] Config validation mode (`-validate` flag)
- [x] Example `Nettlefile` in `test/` and `docker/`
