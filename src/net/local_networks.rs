//! On-link local-network enumeration and the connect-time split-tunnel
//! overlap check — the desktop port of ezvpn-apple
//! `TunnelCore/LocalNetworks.swift`.
//!
//! Routing a subnet the host is currently on into the tunnel would cut off
//! on-link hosts, including the gateway carrying the tunnel's own underlay,
//! so `VpnClient::connect` refuses to start on a conflict (see
//! `docs/Desktop-Overlap-and-Network-Change-Plan.md` §1).

use crate::error::VpnError;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::net::IpAddr;

/// Prefixes at or below this length are the full-tunnel mechanism — default
/// routes and the `/1` half-routes `expand_default_route*` installs — and are
/// exempt from the overlap check. Full tunnel is a supported desktop mode
/// that relies on connected-route specificity plus the global-scope bypass
/// set; only a *specific* routed prefix overlapping an on-link subnet is
/// refused (deliberate divergence from iOS, which refuses default routes).
const EXEMPT_MAX_PREFIX_LEN: u8 = 1;

/// One network the host is attached to: the on-link subnet of an up,
/// running, non-loopback interface. Point-to-point links carry no on-link
/// subnet to conflict with and are skipped by `local_networks()` — a filter
/// that also excludes tun/utun devices by flags rather than by name (the
/// client's own tun never exists when the connect-time check runs anyway:
/// the check precedes `create_tun_device`, and a reconnect attempt only
/// starts after the previous device was dropped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalNetwork {
    /// Interface name (e.g. "en0"), for the refusal message.
    pub interface: String,
    /// The on-link subnet, host bits zeroed.
    pub net: IpNet,
}

impl LocalNetwork {
    /// Build from an interface address and prefix length, zeroing host bits.
    /// Returns `None` for an out-of-range prefix length.
    fn new(interface: &str, ip: IpAddr, prefix_len: u8) -> Option<Self> {
        Some(Self {
            interface: interface.to_string(),
            net: IpNet::new(ip, prefix_len).ok()?.trunc(),
        })
    }
}

/// Enumerate the on-link networks of every active broadcast interface.
/// Loopback, point-to-point, not-running, and IPv6 link-local entries are
/// excluded: none of them describe a routable local subnet. On enumeration
/// failure this logs and returns an empty list (fail open, like iOS).
pub fn local_networks() -> Vec<LocalNetwork> {
    let ifaces = match if_addrs::get_if_addrs() {
        Ok(ifaces) => ifaces,
        Err(e) => {
            log::warn!("Failed to enumerate network interfaces: {}", e);
            return Vec::new();
        }
    };
    ifaces
        .iter()
        .filter(|iface| iface.is_oper_up() && !iface.is_loopback() && !iface.is_p2p())
        .filter_map(|iface| {
            let (ip, prefix_len) = match &iface.addr {
                // IPv4 link-local (169.254/16, APIPA) is deliberately kept:
                // the iOS reference skips only IPv6 link-local, which unlike
                // APIPA is present on every interface unconditionally.
                if_addrs::IfAddr::V4(a) => (IpAddr::V4(a.ip), a.prefixlen),
                if_addrs::IfAddr::V6(a) => {
                    // Link-local lives on every interface and never routes.
                    if a.ip.is_unicast_link_local() {
                        return None;
                    }
                    (IpAddr::V6(a.ip), a.prefixlen)
                }
            };
            LocalNetwork::new(&iface.name, ip, prefix_len)
        })
        .collect()
}

/// The first configured split-tunnel route that overlaps a network the host
/// is currently on. Routes are checked in order, IPv4 then IPv6 (iOS
/// parity); full-tunnel prefixes are exempt (see [`EXEMPT_MAX_PREFIX_LEN`]).
pub fn split_tunnel_conflict(
    routes: &[Ipv4Net],
    routes6: &[Ipv6Net],
    locals: &[LocalNetwork],
) -> Option<(IpNet, LocalNetwork)> {
    let routes4 = routes.iter().copied().map(IpNet::V4);
    let routes6 = routes6.iter().copied().map(IpNet::V6);
    for route in routes4.chain(routes6) {
        if route.prefix_len() <= EXEMPT_MAX_PREFIX_LEN {
            continue;
        }
        if let Some(local) = locals.iter().find(|l| overlaps(&route, &l.net)) {
            return Some((route, local.clone()));
        }
    }
    None
}

/// [`split_tunnel_conflict`] mapped to the typed refusal error. Shared by the
/// connect-time check and the mid-session watcher so both surface the exact
/// same error for a given conflict.
pub fn overlap_error(
    routes: &[Ipv4Net],
    routes6: &[Ipv6Net],
    locals: &[LocalNetwork],
) -> Option<VpnError> {
    split_tunnel_conflict(routes, routes6, locals).map(|(route, local)| {
        VpnError::RouteOverlapsLocalNetwork {
            route,
            local: local.net,
            interface: local.interface,
        }
    })
}

/// Whether any configured route is subject to the overlap check at all (i.e.
/// not full-tunnel-exempt). When false the mid-session watcher has nothing
/// that could ever conflict and need not run.
pub fn has_refusable_routes(routes: &[Ipv4Net], routes6: &[Ipv6Net]) -> bool {
    routes.iter().any(|r| r.prefix_len() > EXEMPT_MAX_PREFIX_LEN)
        || routes6.iter().any(|r| r.prefix_len() > EXEMPT_MAX_PREFIX_LEN)
}

/// Two prefixes overlap iff one contains the other's network address.
/// `ipnet` treats mixed address families as disjoint, so IPv4 routes never
/// cross-check against IPv6 locals or vice versa.
fn overlaps(a: &IpNet, b: &IpNet) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local(interface: &str, cidr: &str) -> LocalNetwork {
        LocalNetwork {
            interface: interface.to_string(),
            net: cidr.parse().unwrap(),
        }
    }

    /// Fixture mirroring the iOS SplitTunnelConflictTests home network.
    fn home() -> Vec<LocalNetwork> {
        vec![
            local("en0", "192.168.1.0/24"),
            local("en0", "fd12:3456:789a:1::/64"),
        ]
    }

    fn v4(cidrs: &[&str]) -> Vec<Ipv4Net> {
        cidrs.iter().map(|c| c.parse().unwrap()).collect()
    }

    fn v6(cidrs: &[&str]) -> Vec<Ipv6Net> {
        cidrs.iter().map(|c| c.parse().unwrap()).collect()
    }

    #[test]
    fn test_no_conflict() {
        assert_eq!(split_tunnel_conflict(&[], &[], &home()), None);
        assert_eq!(
            split_tunnel_conflict(&v4(&["10.0.0.0/8"]), &v6(&["fd99::/64"]), &home()),
            None
        );
    }

    #[test]
    fn test_ipv4_conflict() {
        let (route, local) =
            split_tunnel_conflict(&v4(&["192.168.0.0/16"]), &[], &home()).unwrap();
        assert_eq!(route.to_string(), "192.168.0.0/16");
        assert_eq!(local.net.to_string(), "192.168.1.0/24");
        assert_eq!(local.interface, "en0");
    }

    #[test]
    fn test_ipv6_conflict() {
        let (route, local) =
            split_tunnel_conflict(&[], &v6(&["fd12:3456:789a::/48"]), &home()).unwrap();
        assert_eq!(route.to_string(), "fd12:3456:789a::/48");
        assert_eq!(local.net.to_string(), "fd12:3456:789a:1::/64");
        assert_eq!(local.interface, "en0");
    }

    #[test]
    fn test_families_do_not_cross_check() {
        let locals = vec![local("en0", "fd00::/64")];
        assert_eq!(
            split_tunnel_conflict(&v4(&["10.0.0.0/8"]), &[], &locals),
            None
        );
    }

    // Deliberate divergence from iOS (which refuses default routes): full
    // tunnel is a supported desktop mode, so /0 and the /1 halves that
    // `expand_default_route*` installs are exempt.
    #[test]
    fn test_default_and_half_routes_exempt() {
        assert_eq!(
            split_tunnel_conflict(&v4(&["0.0.0.0/0"]), &v6(&["::/0"]), &home()),
            None
        );
        assert_eq!(
            split_tunnel_conflict(
                &v4(&["0.0.0.0/1", "128.0.0.0/1"]),
                &v6(&["::/1", "8000::/1"]),
                &home()
            ),
            None
        );
    }

    #[test]
    fn test_specific_route_conflicts_alongside_exempt_default() {
        let (route, local) =
            split_tunnel_conflict(&v4(&["0.0.0.0/1", "192.168.0.0/16"]), &[], &home()).unwrap();
        assert_eq!(route.to_string(), "192.168.0.0/16");
        assert_eq!(local.net.to_string(), "192.168.1.0/24");
    }

    #[test]
    fn test_first_conflict_wins() {
        let mut locals = home();
        locals.push(local("en1", "10.9.0.0/16"));
        let (route, local) =
            split_tunnel_conflict(&v4(&["10.0.0.0/8", "192.168.0.0/16"]), &[], &locals).unwrap();
        assert_eq!(route.to_string(), "10.0.0.0/8");
        assert_eq!(local.interface, "en1");
    }

    #[test]
    fn test_overlap_error_maps_conflict_to_typed_error() {
        let err = overlap_error(&v4(&["192.168.0.0/16"]), &[], &home()).unwrap();
        assert_eq!(
            err.to_string(),
            "refusing to start: split-tunnel route 192.168.0.0/16 \
             overlaps current network 192.168.1.0/24 on en0"
        );
        assert!(overlap_error(&v4(&["10.0.0.0/8"]), &[], &home()).is_none());
    }

    #[test]
    fn test_has_refusable_routes() {
        assert!(!has_refusable_routes(&[], &[]));
        // Full-tunnel prefixes are exempt, so nothing is refusable.
        assert!(!has_refusable_routes(
            &v4(&["0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1"]),
            &v6(&["::/0", "::/1", "8000::/1"])
        ));
        assert!(has_refusable_routes(&v4(&["10.0.0.0/8"]), &[]));
        assert!(has_refusable_routes(&[], &v6(&["fd00::/8"])));
    }

    #[test]
    fn test_local_network_zeroes_host_bits() {
        let ln = LocalNetwork::new("en0", "192.168.1.23".parse().unwrap(), 24).unwrap();
        assert_eq!(ln.net.to_string(), "192.168.1.0/24");
    }

    // Invariants over the live interface list (like the iOS
    // testLiveLocalNetworksExcludeNonRoutable); vacuously true on hosts
    // with no active interfaces, so safe under CI variability.
    #[test]
    fn test_live_local_networks_exclude_non_routable() {
        for ln in local_networks() {
            assert!(!ln.net.addr().is_loopback(), "loopback leaked: {:?}", ln);
            if let IpNet::V6(net) = ln.net {
                assert!(
                    !net.addr().is_unicast_link_local(),
                    "IPv6 link-local leaked: {:?}",
                    ln
                );
            }
            assert!(!ln.interface.starts_with("lo"), "loopback iface: {:?}", ln);
        }
    }
}
