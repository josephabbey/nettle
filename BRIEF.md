# Nettle

This is the modern replacement for dnsmasq (with fewer options and more features).

This is not a highly configurable piece of software, it is meant to be fit for my purpose specifically.

That being said, it is quite configurable.

## Components

This will be composed of multiple components that will be parallel and communicate over a bus.

### Config

This will parse the conffile style Nettlefile and provide a structured configuration.

### DNS

This is a recursive DNS server, it will resolve all types of query but it only serves A and CNAME records for local domains and NS records to point to connected Nettle instances (Connect component).

Keep it simple.

Other components will publish messages on the bus to add records to the DNS server.

### DHCP

This is a DHCP server that will provide IP addresses to connected clients.

Keep it simple.

When a host is given an address, the DNS server will be notified to add a record for that host.

The DHCP server must also serve static routes for VPN and Connect components. Sent via the bus.

There may be a specialised second DHCP server for the guest network that serves a different range of IP addresses on a different interface.

The server must also manage leases for the VPN clients. Devices that roam networks (such as phones) will not have static IP addresses, they may be on any connected network or via the VPN but should receive the same hostname and be accessible at the same DNS name.

### VPN

This is a simple wireguard server. Clients can connect and access the LAN and WAN.

### Connect

This is a complex Nettle to Nettle connection layer. It binds two LANs together using wireguard.

It must ensure during the handshake that there are no collisions in the configurations (no colliding ip ranges).

Every device on one LAN is accessible directly on the other LAN via a static route and a tunnel.

The pairing process will be cryptographic and use QR codes that are scanned through the web interface with a phone.

### Webserver

This is a simple webserver that facilitates the communication between two Nettle instances and the handshake process.

It also is a GUI where VPN configurations can be generated and managed.

It will display tables of leases and VPN connections.

And a network map (graph) visualising connections and routes.

Keep it simple.

The expectation is that Caddy will be used seperately for SSL and to proxy sites.

Authentication will be handled through OIDC (Authelia).
