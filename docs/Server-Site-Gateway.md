# Server as a Site Gateway

How to set up the host that runs `ezvpn server` so that remote clients reach
the other devices on its network at their original addresses. This is the
"whole site through one gateway device" use in the README's
[Deployment Model](../README.md#deployment-model).

None of this is needed when clients only reach the server host itself at its
VPN IP: that traffic is never forwarded.

`ezvpn` does not configure any of it. Forwarding, NAT, and routing stay with
the OS, set once with your normal tooling. The examples are for a Linux server
host with these values:

| Value | Meaning |
| --- | --- |
| `eth0` | The server host's interface on the site's LAN. |
| `10.0.0.0/24` | The server config's `network` (IPv4 VPN prefix). |
| `fd00::/64` | The server config's `network6` (IPv6 VPN prefix). |
| `192.168.1.0/24` | The site's LAN, which clients route with `--route`. |

The server host does not have to be the site's router. Any always-on host on
the LAN works.

## 1. Enable IP forwarding

```bash
sysctl -w net.ipv4.ip_forward=1
sysctl -w net.ipv6.conf.all.forwarding=1
```

Persist them in `/etc/sysctl.d/`.

On Linux, enabling IPv6 forwarding makes the kernel stop accepting router
advertisements. A server host that gets its own IPv6 default route by SLAAC
loses it unless that interface is set to keep accepting them:

```bash
sysctl -w net.ipv6.conf.eth0.accept_ra=2
```

Turning forwarding on does not open the firewall. A host that filters routed
traffic (UFW, firewalld, or a default-drop `FORWARD` policy) also needs a rule
that lets the VPN prefix through to the LAN, and the replies back. NAT rules do
not do this; netfilter filters forwarded packets separately:

```bash
iptables -A FORWARD -s 10.0.0.0/24 -o eth0 -j ACCEPT
iptables -A FORWARD -d 10.0.0.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```

The same applies to IPv6 with `ip6tables` and the `network6` prefix.

## 2. Give the VPN prefix a return path

A device on the LAN replies to the client's VPN address, and that reply has to
come back to the server host. Either hide the VPN address behind the server
(NAT) or tell the site where it lives (routing). The two can be mixed per
address family: NAT for IPv4 and routing for IPv6 is a common combination.

### NAT

The usual choice for IPv4. Devices on the LAN see the connection as coming from
the server host:

```bash
iptables -t nat -A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE
```

The same works for IPv6 with `ip6tables` and the `network6` prefix.

### Routing, without NAT

Devices on the LAN see each client's real VPN address, and the site needs a
route for the VPN prefix that points at the server host:

- If the server host is already the site's default router, nothing more is
  needed. Replies come to it anyway.
- Otherwise add a static route for the VPN prefix on the site's router, with
  the server host as the next hop.
- For IPv6, the server host can announce the route itself in a router
  advertisement, so nothing on the router changes. With `radvd`:

  ```
  # /etc/radvd.conf on the ezvpn server host
  interface eth0 {
      AdvSendAdvert on;
      AdvDefaultLifetime 0;    # a route only: never the LAN's default router
      route fd00::/64 { };     # the server config's `network6` prefix
  };
  ```

  `AdvDefaultLifetime 0` matters: without it the server host also advertises
  itself as a default router for the whole LAN.

  The route is carried as an RFC 4191 Route Information Option, and only
  devices that support that option pick it up. Support is not universal:
  `radvd`'s own example config calls it "not very widely supported". A Linux
  device whose kernel handles router advertisements ignores it unless its
  `net.ipv6.conf.<interface>.accept_ra_rt_info_max_plen` sysctl is at least
  the prefix length (`64` here), while systemd-networkd and NetworkManager
  handle router advertisements in userspace and accept the route by default.
  For devices that ignore it, add the static route on the site's router as
  above, or fall back to NAT.

## 3. Route the site from the client

```bash
sudo ezvpn client start \
  --server-node-id <SERVER_ENDPOINT_ID> \
  --auth-key-file ./client.key \
  --route 192.168.1.0/24 \
  --route6 <SITE_IPV6_PREFIX>
```

A device at `192.168.1.20` on the LAN is then `192.168.1.20` from the client.

## Notes

- All of the above can be permanent. The NAT rule and the announced route
  both key on the VPN prefix, so they are inert while the tunnel is down.
  There are no up/down hooks to script.
- No firewall rule is needed to keep clients apart (the server drops
  client-to-client packets itself) or to open an inbound port for `ezvpn`
  (there is none). See
  [Server NAT and Firewall](../README.md#server-nat-and-firewall). Forwarded
  traffic from the VPN prefix to the LAN is a separate matter, covered in
  step 1.
- A client refuses a `--route` that overlaps the network it is sitting on, so
  a site LAN in a commonly used range (`192.168.1.0/24`, say) cannot be
  reached from another LAN numbered the same way. See "Split-Tunnel Overlap
  Refusal (Client)" in [Architecture.md](Architecture.md).
- To resolve the site's internal DNS names from a client, see
  [Client-Split-DNS.md](Client-Split-DNS.md).
