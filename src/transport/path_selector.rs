//! Client path selector that keeps the tunnel off direct paths to excluded
//! server addresses (`[iroh].exclude_direct_paths`).
//!
//! iroh advertises every local address of the server as a direct-path
//! candidate, including the address of another VPN it runs (e.g. Tailscale's
//! `100.64.0.0/10`). When the client is on that VPN too, the overlay path is
//! reachable, often wins on RTT, and ezvpn ends up tunnelled inside the other
//! VPN. Whether that is wanted depends on the deployment, and an overlay cannot
//! be told apart from a LAN by address alone, so the exclusion is opt-in.
//!
//! [`ExcludingPathSelector`] mirrors iroh's default `BiasedRttPathSelector`
//! (not public) — direct paths beat the relay, lowest RTT wins with IPv6
//! [`IPV6_RTT_ADVANTAGE`] ahead, and a same-tier switch needs
//! [`RTT_SWITCHING_MIN`] of improvement — and only drops the excluded direct
//! paths from the candidates. iroh still probes those addresses; they just
//! never carry traffic. With nothing else direct, the relay carries it.

use ipnet::IpNet;
use iroh::endpoint::transports::{
    Addr, FourTuple, PathSelection, PathSelectionContext, PathSelector,
};
use std::time::Duration;

/// How far IPv6 is preferred over IPv4 (same as iroh's default selector).
const IPV6_RTT_ADVANTAGE: Duration = Duration::from_millis(3);

/// Improvement a same-tier candidate needs before the selection switches to it
/// (same as iroh's default selector), so jitter does not flap the path.
const RTT_SWITCHING_MIN: Duration = Duration::from_millis(5);

/// Path selector that never selects a direct path whose remote IP falls in one
/// of the excluded networks. See the module docs.
#[derive(Debug)]
pub struct ExcludingPathSelector {
    excluded: Vec<IpNet>,
}

impl ExcludingPathSelector {
    pub fn new(excluded: Vec<IpNet>) -> Self {
        Self { excluded }
    }

    fn is_excluded(&self, path: &FourTuple) -> bool {
        match path.remote() {
            Addr::Ip(addr) => {
                let ip = addr.ip().to_canonical();
                self.excluded.iter().any(|net| net.contains(&ip))
            }
            _ => false,
        }
    }

    /// Sort key, lower is better: the relay tier after every direct path, then
    /// the biased RTT.
    fn sort_key(path: &FourTuple, rtt: Duration) -> (bool, i128) {
        let mut biased = rtt.as_nanos() as i128;
        if let Addr::Ip(addr) = path.remote()
            && addr.is_ipv6()
        {
            biased -= IPV6_RTT_ADVANTAGE.as_nanos() as i128;
        }
        (path.is_relay(), biased)
    }

    /// Index of the candidate to switch to, or `None` to keep the current
    /// selection.
    fn choose(&self, current: Option<&FourTuple>, candidates: &[(&FourTuple, Duration)]) -> Option<usize> {
        let mut best: Option<(usize, (bool, i128))> = None;
        let mut current_key: Option<(bool, i128)> = None;
        for (i, (path, rtt)) in candidates.iter().enumerate() {
            if self.is_excluded(path) {
                continue;
            }
            let key = Self::sort_key(path, *rtt);
            if Some(*path) == current && current_key.is_none_or(|c| key < c) {
                current_key = Some(key);
            }
            if best.is_none_or(|(_, b)| key < b) {
                best = Some((i, key));
            }
        }
        let (best_idx, (best_tier, best_biased)) = best?;
        match current_key {
            // No current path, or it is excluded: take the best.
            None => Some(best_idx),
            Some((current_tier, _)) if current_tier != best_tier => Some(best_idx),
            Some((_, current_biased))
                if best_biased + RTT_SWITCHING_MIN.as_nanos() as i128 <= current_biased =>
            {
                Some(best_idx)
            }
            Some(_) => None,
        }
    }
}

impl PathSelector for ExcludingPathSelector {
    fn select(&self, ctx: &PathSelectionContext<'_>) -> PathSelection {
        // Skip paths whose stats can't be read (e.g. closed concurrently).
        let paths: Vec<_> = ctx
            .paths()
            .filter_map(|psd| psd.stats().map(|stats| (psd, stats.rtt)))
            .collect();
        let candidates: Vec<_> = paths
            .iter()
            .map(|(psd, rtt)| (psd.network_path(), *rtt))
            .collect();
        let mut selection = PathSelection::none();
        if let Some(i) = self.choose(ctx.current(), &candidates) {
            selection.set(&paths[i].0);
        }
        selection
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::{RelayUrl, SecretKey};
    use std::net::SocketAddr;

    fn ip(addr: &str) -> FourTuple {
        FourTuple::from_remote(Addr::Ip(addr.parse::<SocketAddr>().unwrap()))
    }

    fn relay() -> FourTuple {
        let url: RelayUrl = "https://relay.example.com".parse().unwrap();
        FourTuple::from_remote(Addr::Relay(url, SecretKey::from_bytes(&[7; 32]).public()))
    }

    fn ms(v: u64) -> Duration {
        Duration::from_millis(v)
    }

    fn tailscale() -> ExcludingPathSelector {
        ExcludingPathSelector::new(vec![
            "100.64.0.0/10".parse().unwrap(),
            "fd7a:115c:a1e0::/48".parse().unwrap(),
        ])
    }

    #[test]
    fn excluded_direct_path_is_never_chosen() {
        let (ts, lan, r) = (ip("100.96.115.31:4000"), ip("10.22.40.61:4000"), relay());
        let cands = [(&ts, ms(1)), (&lan, ms(8)), (&r, ms(50))];
        assert_eq!(tailscale().choose(None, &cands), Some(1));
    }

    #[test]
    fn excluded_ipv6_and_mapped_ipv4_are_matched() {
        let ts6 = ip("[fd7a:115c:a1e0::1]:4000");
        let mapped = ip("[::ffff:100.96.115.31]:4000");
        let r = relay();
        let cands = [(&ts6, ms(1)), (&mapped, ms(1)), (&r, ms(50))];
        assert_eq!(tailscale().choose(None, &cands), Some(2));
    }

    #[test]
    fn falls_back_to_relay_when_only_excluded_direct_paths() {
        let (ts, r) = (ip("100.96.115.31:4000"), relay());
        let cands = [(&ts, ms(1)), (&r, ms(50))];
        assert_eq!(tailscale().choose(None, &cands), Some(1));
    }

    #[test]
    fn leaves_excluded_current_path() {
        let (ts, lan) = (ip("100.96.115.31:4000"), ip("10.22.40.61:4000"));
        // The current path is excluded, so even a slower allowed path replaces it.
        let cands = [(&ts, ms(1)), (&lan, ms(4))];
        assert_eq!(tailscale().choose(Some(&ts), &cands), Some(1));
    }

    #[test]
    fn no_exclusions_behaves_like_default() {
        let sel = ExcludingPathSelector::new(vec![]);
        let (ts, lan, r) = (ip("100.96.115.31:4000"), ip("10.22.40.61:4000"), relay());
        let cands = [(&ts, ms(1)), (&lan, ms(8)), (&r, ms(0))];
        // Direct beats the relay regardless of RTT; lowest RTT wins.
        assert_eq!(sel.choose(None, &cands), Some(0));
    }

    #[test]
    fn same_tier_switch_needs_min_improvement() {
        let sel = ExcludingPathSelector::new(vec![]);
        let (a, b) = (ip("10.0.0.1:1"), ip("10.0.0.2:1"));
        // 4 ms better: stay on the current path.
        assert_eq!(sel.choose(Some(&a), &[(&a, ms(10)), (&b, ms(6))]), None);
        // 5 ms better: switch.
        assert_eq!(sel.choose(Some(&a), &[(&a, ms(10)), (&b, ms(5))]), Some(1));
    }

    #[test]
    fn relay_to_direct_switches_immediately() {
        let sel = ExcludingPathSelector::new(vec![]);
        let (r, lan) = (relay(), ip("10.22.40.61:4000"));
        assert_eq!(sel.choose(Some(&r), &[(&r, ms(1)), (&lan, ms(40))]), Some(1));
    }

    #[test]
    fn ipv6_gets_rtt_advantage() {
        let sel = ExcludingPathSelector::new(vec![]);
        let (v4, v6) = (ip("10.0.0.1:1"), ip("[2001:db8::1]:1"));
        assert_eq!(sel.choose(None, &[(&v4, ms(10)), (&v6, ms(12))]), Some(1));
    }
}
