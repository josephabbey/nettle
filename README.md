# Nettle

Nettle is a small network control daemon built around a conffile-style config.
This starter now has a typed config loader, structured logging, a simple event bus,
and service shells for DNS, DHCP, VPN, connect, and web.

## Run

Validate the sample config:

```sh
go run . -validate
```

Run the daemon with the sample config:

```sh
go run . -config test/Nettlefile
```

Optional logging overrides:

```sh
go run . -config test/Nettlefile -log-level debug -log-format json
```

## Docker

Build the container locally:

```sh
docker build -t nettle .
```

Run with Docker Compose:

```sh
docker compose up --build
```

The Compose file runs a Docker-safe DNS-only config on port `1053/udp` so it comes
up cleanly without privileged networking. Mount your own `Nettlefile` at
`/config/Nettlefile` if you want to run the full DNS/DHCP stack in a host-networked
deployment.

## Publishing

GitHub Actions builds the image on pushes to `main`/`master`, tags, and manual runs,
then publishes it to `ghcr.io/<owner>/nettle`.

## Config Shape

The config file has one global block plus per-host matcher blocks.

- `tld`, `hosts`, and `ethers` configure the top-level network identity.
- `dhcp { ... }` configures the DHCP pool, lease time, gateway, DNS servers, and interface.
- `dns { ... }` configures the DNS listener and upstreams.
- `vpn { ... }` configures the VPN address assignment.
- `glue <address> { connect <peer> { nodns } }` models inter-nettle linking.
- Matcher blocks like `netley, *.netley.ruins { ip 192.168.0.45 }` define local DNS records.
- `log { level info format text }` can override the default logging setup.

## Notes

- The config loader uses the GitHub-hosted `conffile` parser from `github.com/josephabbey/conffile`.
- Logging is based on the Go standard library `log/slog` and is installed globally at startup.
- DNS and DHCP are implemented as modular services with a shared in-process bus.
