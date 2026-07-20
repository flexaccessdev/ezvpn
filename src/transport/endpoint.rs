//! Common endpoint helpers for iroh tunnel connections.

use crate::transport::build_quic_transport_config;
use crate::tunnel::signaling::VPN_ALPN;
use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use iroh::{
    Endpoint, EndpointId, RelayMap, RelayMode, RelayUrl, SecretKey,
    address_lookup::{DnsAddressLookup, PkarrPublisher},
    endpoint::{Builder as EndpointBuilder, presets},
};
use log::info;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub const RELAY_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Relay configuration, resolved once from the raw config strings.
///
/// This is the single source of the default-vs-custom distinction. Both modes
/// enable iroh address lookup (pkarr publishing + DNS resolution of the peer's
/// home relay — see <https://docs.iroh.computer/concepts/address-lookup>); the
/// only difference between them is which relay map iroh uses. See "Relays and
/// Address Lookup" in `docs/Architecture.md`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum RelayConfig {
    /// iroh's default relay map, with n0 address lookup.
    #[default]
    Default,
    /// Custom relay set (parsed, sorted, deduped). Never empty.
    ///
    /// `auth_token`, when set, is sent to every custom relay as an
    /// `Authorization: Bearer <token>` header on the WebSocket upgrade (see
    /// [`Self::relay_mode`]). It is only ever carried by custom relays — the
    /// default relays never receive a token (see [`Self::from_urls_with_token`]).
    Custom {
        urls: Vec<RelayUrl>,
        auth_token: Option<String>,
    },
}

impl RelayConfig {
    /// Parse raw config strings with no relay auth token.
    ///
    /// Thin wrapper over [`Self::from_urls_with_token`]; see there for behavior.
    pub fn from_urls(urls: &[String]) -> Result<Self> {
        Self::from_urls_with_token(urls, None)
    }

    /// Parse raw config strings and attach an optional shared relay auth token.
    ///
    /// Empty input selects the default relays. Parsing fails on the first
    /// malformed URL, so config typos surface at resolve time instead of at each
    /// use site.
    ///
    /// The token is normalized (blank/whitespace-only becomes `None`) and is
    /// **strictly gated to custom relays**: a non-empty token with no custom
    /// relay URLs is a hard error, since the default iroh relays never take a
    /// token. This surfaces the misconfiguration before the endpoint starts.
    pub fn from_urls_with_token(urls: &[String], auth_token: Option<String>) -> Result<Self> {
        let auth_token = auth_token.filter(|t| !t.trim().is_empty());
        if urls.is_empty() {
            if auth_token.is_some() {
                anyhow::bail!(
                    "relay_auth_token requires custom relay_urls; it is not used with the default iroh relays"
                );
            }
            return Ok(Self::Default);
        }
        let mut parsed = urls
            .iter()
            .map(|url| {
                url.parse::<RelayUrl>()
                    .with_context(|| format!("Invalid relay URL: {url}"))
            })
            .collect::<Result<Vec<_>>>()?;
        parsed.sort();
        parsed.dedup();
        Ok(Self::Custom {
            urls: parsed,
            auth_token,
        })
    }

    /// The custom relay URLs; empty for [`RelayConfig::Default`].
    pub fn custom_urls(&self) -> &[RelayUrl] {
        match self {
            Self::Default => &[],
            Self::Custom { urls, .. } => urls,
        }
    }

    /// The shared relay auth token, if configured (custom relays only).
    pub fn relay_auth_token(&self) -> Option<&str> {
        match self {
            Self::Default => None,
            Self::Custom { auth_token, .. } => auth_token.as_deref(),
        }
    }

    pub fn is_custom(&self) -> bool {
        matches!(self, Self::Custom { .. })
    }

    /// The corresponding iroh [`RelayMode`].
    ///
    /// For custom relays, an `auth_token` (when set) is applied to every relay in
    /// the map via [`RelayMap::with_auth_token`], which iroh sends as an
    /// `Authorization: Bearer <token>` header on the relay WebSocket upgrade.
    pub fn relay_mode(&self) -> RelayMode {
        match self {
            Self::Default => RelayMode::Default,
            Self::Custom { urls, auth_token } => {
                let map = RelayMap::from_iter(urls.iter().cloned());
                let map = match auth_token {
                    Some(token) => map.with_auth_token(token.clone()),
                    None => map,
                };
                RelayMode::Custom(map)
            }
        }
    }
}

/// Load secret key from file (base64 encoded).
pub fn load_secret(path: &Path) -> Result<SecretKey> {
    if !path.exists() {
        anyhow::bail!(
            "Secret key file not found: {}\nGenerate one with: ezvpn generate-server-key --output {}",
            path.display(),
            path.display()
        );
    }

    let content = std::fs::read_to_string(path).context("Failed to read secret key file")?;
    load_secret_from_string(content.trim())
}

/// Load secret key from a base64-encoded string.
pub fn load_secret_from_string(base64_key: &str) -> Result<SecretKey> {
    let bytes = BASE64
        .decode(base64_key)
        .context("Invalid base64 in secret key")?;

    SecretKey::try_from(&bytes[..]).context("Invalid secret key (must be 32 bytes)")
}

/// Get public key (EndpointId) from secret key.
pub fn secret_to_endpoint_id(secret: &SecretKey) -> EndpointId {
    secret.public()
}

/// Print relay configuration status messages.
pub fn print_relay_status(relay_config: &RelayConfig) {
    match relay_config.custom_urls().len() {
        0 => {}
        1 => info!("Using custom relay server"),
        n => info!("Using {} custom relay servers", n),
    }
}

/// Warn (Linux only) when `net.core.rmem_max` / `net.core.wmem_max` would clamp
/// the UDP socket buffer that iroh requests, silently shrinking burst tolerance.
///
/// iroh's socket layer (netwatch) requests a 7 MiB `SO_RCVBUF`/`SO_SNDBUF`, but
/// Linux silently caps the request at these sysctls (default ≈ 208 KiB) and
/// reports no error, so a too-small ceiling drops inbound datagram bursts with no
/// feedback. We do not own the socket, so this is detect-and-warn only — it never
/// mutates host sysctls. On non-Linux targets it compiles to a no-op.
fn warn_if_socket_buffer_capped() {
    #[cfg(target_os = "linux")]
    {
        const TARGET: usize = crate::transport::IROH_SOCKET_BUFFER_REQUEST;
        for (knob, path, sock) in [
            (
                "net.core.rmem_max",
                "/proc/sys/net/core/rmem_max",
                "SO_RCVBUF",
            ),
            (
                "net.core.wmem_max",
                "/proc/sys/net/core/wmem_max",
                "SO_SNDBUF",
            ),
        ] {
            match std::fs::read_to_string(path) {
                Ok(contents) => match contents.trim().parse::<usize>() {
                    // The Linux cap applies to the requested (un-doubled) value,
                    // so compare the sysctl directly against the target.
                    Ok(current) if current < TARGET => log::warn!(
                        "{knob} = {current} is below {TARGET} (7 MiB); the kernel will silently \
                         clamp iroh's {sock} to this size, dropping inbound datagram bursts under \
                         load (seen as inner-TCP retransmits). Raise it to use the full buffer: \
                         sudo sysctl -w {knob}={TARGET}"
                    ),
                    Ok(current) => log::debug!("{knob} = {current} (>= {TARGET}, ok)"),
                    Err(e) => log::debug!("could not parse {path}: {e}"),
                },
                Err(e) => log::debug!("could not read {path}: {e}"),
            }
        }
    }
}

/// Create a base endpoint builder with common configuration.
///
/// iroh address lookup (pkarr publishing + DNS-based lookup of
/// `_iroh.<endpoint-id>.dns.iroh.link`, see
/// <https://docs.iroh.computer/concepts/address-lookup>) is enabled uniformly,
/// for both the default relays and custom relay sets. The relay map differs
/// between the two, but in both cases the server publishes its current home
/// relay and a client resolves it by endpoint ID.
pub fn create_endpoint_builder(relay_config: &RelayConfig) -> Result<EndpointBuilder> {
    warn_if_socket_buffer_capped();
    let transport_config = build_quic_transport_config()?;
    // iroh 1.0 requires the crypto provider to be set explicitly on the
    // builder when starting from the `Empty` preset — the `tls-ring` feature
    // only makes the ring backend available, it does not wire it in.
    let builder = Endpoint::builder(presets::Empty)
        .relay_mode(relay_config.relay_mode())
        .transport_config(transport_config)
        .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()))
        // n0 address lookup (pkarr publishing + DNS-based lookup), always on.
        .address_lookup(PkarrPublisher::n0_dns())
        .address_lookup(DnsAddressLookup::n0_dns());

    Ok(builder)
}

/// Create the VPN server's iroh endpoint with an optional persistent identity,
/// waiting for it to come online (bounded by [`RELAY_CONNECT_TIMEOUT`]).
///
/// A single endpoint serves both the default and custom relay modes: address
/// lookup is always enabled, so the server publishes its current home relay and
/// clients resolve it by endpoint ID (iroh's relay failover re-homes and
/// republishes on its own).
pub async fn create_server_endpoint(
    relay_config: &RelayConfig,
    secret: Option<SecretKey>,
) -> Result<Endpoint> {
    print_relay_status(relay_config);

    let mut builder = create_endpoint_builder(relay_config)?.alpns(vec![VPN_ALPN.to_vec()]);

    if let Some(secret) = secret {
        builder = builder.secret_key(secret);
    }

    let endpoint = builder
        .bind()
        .await
        .context("Failed to create iroh endpoint")?;

    // Wait for endpoint to come online with timeout
    info!(
        "Waiting for endpoint to come online (timeout: {}s)...",
        RELAY_CONNECT_TIMEOUT.as_secs()
    );
    match tokio::time::timeout(RELAY_CONNECT_TIMEOUT, endpoint.online()).await {
        Ok(()) => {}
        Err(_) => anyhow::bail!(
            "Endpoint failed to come online after {}s - check relay server connectivity",
            RELAY_CONNECT_TIMEOUT.as_secs()
        ),
    }

    Ok(endpoint)
}

/// Create a client endpoint.
/// If a secret key is provided, the client will use a persistent identity for authentication.
pub async fn create_client_endpoint(
    relay_config: &RelayConfig,
    secret_key: Option<&SecretKey>,
) -> Result<Endpoint> {
    print_relay_status(relay_config);

    let mut builder = create_endpoint_builder(relay_config)?;

    // Set the secret key for persistent identity (used for authentication)
    if let Some(secret) = secret_key {
        builder = builder.secret_key(secret.clone());
    }

    let endpoint = builder
        .bind()
        .await
        .context("Failed to create iroh endpoint")?;

    // Wait for endpoint to come online with timeout
    info!(
        "Waiting for endpoint to come online (timeout: {}s)...",
        RELAY_CONNECT_TIMEOUT.as_secs()
    );
    match tokio::time::timeout(RELAY_CONNECT_TIMEOUT, endpoint.online()).await {
        Ok(()) => {}
        Err(_) => anyhow::bail!(
            "Endpoint failed to come online after {}s - check relay server connectivity",
            RELAY_CONNECT_TIMEOUT.as_secs()
        ),
    }

    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELAY: &str = "https://relay.example.com./";

    #[test]
    fn empty_urls_no_token_is_default() {
        let cfg = RelayConfig::from_urls_with_token(&[], None).unwrap();
        assert_eq!(cfg, RelayConfig::Default);
        assert!(!cfg.is_custom());
        assert_eq!(cfg.relay_auth_token(), None);
    }

    #[test]
    fn blank_token_without_urls_is_default() {
        // A whitespace-only token normalizes to None, so it is not an error.
        let cfg = RelayConfig::from_urls_with_token(&[], Some("   ".to_string())).unwrap();
        assert_eq!(cfg, RelayConfig::Default);
    }

    #[test]
    fn token_without_custom_urls_is_error() {
        let err = RelayConfig::from_urls_with_token(&[], Some("secret".to_string()))
            .expect_err("token without custom relays must be rejected");
        assert!(
            err.to_string()
                .contains("relay_auth_token requires custom relay_urls"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn malformed_custom_url_is_rejected_without_token() {
        // Custom relays are always parse-validated, independent of any token.
        let err = RelayConfig::from_urls_with_token(&["not a url".to_string()], None)
            .expect_err("malformed relay URL must be rejected");
        assert!(
            err.to_string().contains("Invalid relay URL"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn custom_urls_without_token() {
        let cfg = RelayConfig::from_urls_with_token(&[RELAY.to_string()], None).unwrap();
        assert!(cfg.is_custom());
        assert_eq!(cfg.custom_urls().len(), 1);
        assert_eq!(cfg.relay_auth_token(), None);
        assert!(matches!(cfg.relay_mode(), RelayMode::Custom(_)));
    }

    #[test]
    fn custom_urls_with_token_retained() {
        let cfg =
            RelayConfig::from_urls_with_token(&[RELAY.to_string()], Some("secret".to_string()))
                .unwrap();
        assert!(cfg.is_custom());
        assert_eq!(cfg.relay_auth_token(), Some("secret"));
        assert!(matches!(cfg.relay_mode(), RelayMode::Custom(_)));
    }

    #[test]
    fn token_is_trimmed_to_none_with_custom_urls() {
        // A blank token alongside custom relays is simply no token, not an error.
        let cfg =
            RelayConfig::from_urls_with_token(&[RELAY.to_string()], Some("  ".to_string())).unwrap();
        assert!(cfg.is_custom());
        assert_eq!(cfg.relay_auth_token(), None);
    }

    #[test]
    fn from_urls_carries_no_token() {
        let cfg = RelayConfig::from_urls(&[RELAY.to_string()]).unwrap();
        assert_eq!(cfg.relay_auth_token(), None);
    }
}
