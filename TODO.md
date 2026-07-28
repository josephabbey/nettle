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
- [ ] NS record serving for connected Nettle instances (Connect component)
- [ ] Automatic upstream registration from connected instances

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
- [ ] VPN client lease management (roaming between networks/WiFi/VPN)
- [x] Lease persistence to disk

## VPN Service (`services/vpn.go`)

- [ ] WireGuard server — **stub only**, no implementation
- [ ] WireGuard interface management
- [ ] Client key/configuration generation
- [ ] LAN/WAN access for connected clients
- [ ] Route announcement via bus for DHCP to serve

## Connect Service (`services/connect.go`)

- [ ] Nettle-to-Nettle tunnel — **stub only**, no implementation
- [ ] WireGuard tunnel management
- [ ] Handshake protocol
- [ ] IP range collision detection
- [ ] Static route setup across LANs
- [ ] QR code pairing flow
- [ ] Web UI pairing interface
- [ ] DNS NS record registration for connected instances
- [ ] Cross-LAN device accessibility

## Web Service (`services/web.go`)

- [x] HTTP server with embedded assets
- [x] REST API: `/api/state`, `/api/leases`, `/api/dns-records`, `/api/static-hosts`
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
- [ ] VPN configuration generation page
- [ ] VPN connections table/status
- [ ] Network map (graph visualization of connections/routes)
- [ ] OIDC/Authelia authentication integration
- [ ] Connect pairing/handshake page
- [ ] VPN client config download
- [ ] Caddy reverse-proxy guidance or auto-config

## Event Bus (`bus/`)

- [x] Pub/sub hub with generics-free `Event any` interface
- [x] `Subscribe` with buffer size + unsubscribe
- [x] `Publish` with context cancellation
- [x] Graceful `Close`

## Domain Types (`domain/`)

- [x] `DNSRecord`, `Lease`, `Route`, `Peer`, `StaticHost`
- [x] Event wrappers: `DNSRecordUpserted`, `DHCPLeaseAssigned`, `RouteAnnounced`, `PeerStateChanged`, `StaticHostUpserted`
- [x] `EnsureTLD` helper

## Logging (`logging/`)

- [x] Text and JSON format handlers
- [x] Level configuration
- [x] Component logger helper
- [x] Tests

## Infrastructure

- [x] `main.go` wiring all services
- [x] Graceful shutdown (SIGINT/SIGTERM)
- [x] Dockerfile
- [x] docker-compose (`compose.yaml`)
- [x] GitHub Actions workflow (Docker publish)
- [x] Config validation mode (`-validate` flag)
- [x] Example `Nettlefile` in `test/` and `docker/`
