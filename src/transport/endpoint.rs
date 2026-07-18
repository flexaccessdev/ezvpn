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

/// Parse relay URL strings into a RelayMode.
pub fn parse_relay_mode(relay_urls: &[String]) -> Result<RelayMode> {
    if relay_urls.is_empty() {
        Ok(RelayMode::Default)
    } else {
        let parsed_urls: Vec<RelayUrl> = relay_urls
            .iter()
            .map(|url| url.parse().context(format!("Invalid relay URL: {}", url)))
            .collect::<Result<Vec<_>>>()?;
        let relay_map = RelayMap::from_iter(parsed_urls);
        Ok(RelayMode::Custom(relay_map))
    }
}

/// Print relay configuration status messages.
pub fn print_relay_status(relay_urls: &[String], relay_only: bool, using_custom_relay: bool) {
    if using_custom_relay {
        if relay_urls.len() == 1 {
            info!("Using custom relay server");
        } else {
            info!(
                "Using {} custom relay servers (with failover)",
                relay_urls.len()
            );
        }
    }
    if relay_only {
        info!("Relay-only mode: all traffic will go through the relay server");
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
/// iroh peer discovery (the n0 discovery service — pkarr publishing + DNS-based
/// lookup) is enabled only when using the default relays. A custom relay doubles
/// as the rendezvous point, so discovery is disabled automatically whenever one
/// is configured. (This is iroh peer discovery, not real DNS resolution.)
///
/// # Arguments
/// * `relay_mode` - The relay mode to use
/// * `relay_only` - If true, only use relay connections (no direct P2P).
pub fn create_endpoint_builder(relay_mode: RelayMode, relay_only: bool) -> Result<EndpointBuilder> {
    warn_if_socket_buffer_capped();
    let transport_config = build_quic_transport_config()?;
    // Check before `relay_mode` is moved into the builder below.
    let using_custom_relay = !matches!(relay_mode, RelayMode::Default);
    // iroh 1.0 requires the crypto provider to be set explicitly on the
    // builder when starting from the `Empty` preset — the `tls-ring` feature
    // only makes the ring backend available, it does not wire it in.
    let mut builder = Endpoint::builder(presets::Empty)
        .relay_mode(relay_mode)
        .transport_config(transport_config)
        .crypto_provider(Arc::new(rustls::crypto::ring::default_provider()));

    if relay_only {
        builder = builder.clear_ip_transports();
    }

    if !relay_only {
        if using_custom_relay {
            // Custom relay doubles as the rendezvous point, so the n0 discovery
            // service is unnecessary and is disabled automatically.
            info!("Peer discovery disabled (custom relay in use)");
        } else {
            // Default n0 discovery (DNS-based lookup + pkarr publishing)
            builder = builder
                .address_lookup(PkarrPublisher::n0_dns())
                .address_lookup(DnsAddressLookup::n0_dns());
        }
    }

    Ok(builder)
}

/// Create a server endpoint with optional persistent identity.
pub async fn create_server_endpoint(
    relay_urls: &[String],
    relay_only: bool,
    secret: Option<SecretKey>,
) -> Result<Endpoint> {
    let relay_mode = parse_relay_mode(relay_urls)?;
    let using_custom_relay = !matches!(relay_mode, RelayMode::Default);
    print_relay_status(relay_urls, relay_only, using_custom_relay);

    let mut builder =
        create_endpoint_builder(relay_mode, relay_only)?.alpns(vec![VPN_ALPN.to_vec()]);

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
    relay_urls: &[String],
    relay_only: bool,
    secret_key: Option<&SecretKey>,
) -> Result<Endpoint> {
    let relay_mode = parse_relay_mode(relay_urls)?;
    let using_custom_relay = !matches!(relay_mode, RelayMode::Default);
    print_relay_status(relay_urls, relay_only, using_custom_relay);

    let mut builder = create_endpoint_builder(relay_mode, relay_only)?;

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
