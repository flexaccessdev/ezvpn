# Client Split-DNS (Conditional Forwarding)

Manual, per-OS steps to route **only** an internal zone (and its subdomains) to
an internal resolver, while every other name keeps using the client's normal DNS.
This keeps general internet DNS independent of the internal resolver: if it is
down, only the internal zone fails; everything else is unaffected.

Placeholders used below:

| Placeholder | Meaning |
| --- | --- |
| `<RESOLVER_IP>` | IP of the internal DNS resolver that is authoritative for the internal zone. |
| `<INTERNAL_ZONE>` | The internal zone to route, e.g. `internal.example`. |

The ezvpn desktop client does **not** push DNS or match domains over the tunnel
(`dns_server` / `--dns-server` configure iroh *discovery* DNS only — see the
README). This is by design, not a missing feature: the connector's single
responsibility is tunneling, and DNS and firewall policy are managed outside
it. So resolving the internal zone, whether on the LAN or over the ezvpn
tunnel, relies on the OS-level conditional forwarding below. When `<RESOLVER_IP>`
is only reachable over the tunnel, the server must ensure UDP/53 replies come back
from that same address (e.g. an ipf/NAT redirect rule); the tunnel gateway IP
generally also works as `<RESOLVER_IP>` without such a rule.

> **iOS** is not covered here — iOS has no per-domain DNS UI and its split-DNS is
> applied inside the tunnel by the ezvpn iOS app (`NEDNSSettings.matchDomains`),
> or via a DoT configuration profile off-VPN. See the
> [ezvpn-ios](https://github.com/andrewtheguy/ezvpn-ios) README (Split DNS /
> conditional forwarding).

## Windows 11

Windows has no per-domain DNS setting in the GUI (listing multiple DNS servers
does **not** route by domain). The supported mechanism is the **NRPT** (Name
Resolution Policy Table). Run in an **Administrator** PowerShell:

```powershell
Add-DnsClientNrptRule -Namespace ".<INTERNAL_ZONE>" -NameServers "<RESOLVER_IP>"

Get-DnsClientNrptRule                          # verify
Resolve-DnsName test.<INTERNAL_ZONE>           # test — respects NRPT

# undo
Get-DnsClientNrptRule | ? { $_.Namespace -eq ".<INTERNAL_ZONE>" } | Remove-DnsClientNrptRule -Force
```

Persistent across reboots; deployable fleet-wide via Group Policy (Computer
Config → Policies → Windows Settings → Name Resolution Policy).

**Verify which nameserver a name is routed to.** `Resolve-DnsName` does not print
the responding server, so use the effective NRPT policy:

```powershell
Get-DnsClientNrptPolicy -Effective -Namespace "test.<INTERNAL_ZONE>"
```

- A name **inside** the zone returns a policy with `NameServers : <RESOLVER_IP>` —
  that is the definitive "this name goes to the internal resolver" check.
- A name **outside** the zone (e.g. `example.com`) returns
  `Failed to retrieve NRPT policy`. This looks like an error but is the desired
  result: no NRPT rule matches, so the name resolves via the adapter's normal DNS
  and does **not** depend on the internal resolver.

Quick behavioral cross-check (no extra tooling): `Resolve-DnsName
test.<INTERNAL_ZONE>` succeeds (respects NRPT) while plain `nslookup
test.<INTERNAL_ZONE>` fails — proving the name only resolves when routed to the
internal resolver. For on-wire proof, `pktmon filter add -p 53` +
`pktmon start --etw -m real-time` shows the query leaving for `<RESOLVER_IP>:53`.

**Gotchas:**
- `nslookup` **bypasses NRPT** — it queries the adapter DNS directly and will look
  like the rule is ignored. Always verify with `Resolve-DnsName`.
- Per-adapter DoH ("Encrypted DNS") or a VPN client enforcing its own resolver can
  shortcut the NRPT. Disable those on the adapter if a rule seems ignored.
- The effective policy may display `QueryPolicy : QueryIPv6Only` as a default
  value. It is not actually enforced (A records resolve fine); only investigate it
  if IPv4/A lookups for the zone start failing.

## macOS

```bash
sudo mkdir -p /etc/resolver
printf 'nameserver <RESOLVER_IP>\n' | sudo tee /etc/resolver/<INTERNAL_ZONE>
```

## Linux (systemd-resolved)

On the link facing the network, add the resolver as DNS and route the zone to it:

```bash
resolvectl dns <iface> <RESOLVER_IP>
resolvectl domain <iface> '~<INTERNAL_ZONE>'
```

(The leading `~` marks it a routing-only domain, so only that zone goes to the
internal resolver.)
