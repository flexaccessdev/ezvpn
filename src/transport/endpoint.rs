//! ezvpn's endpoints: what this program layers onto the shared
//! [`flexaccess_iroh::endpoint`] builder — the VPN ALPN, its QUIC transport
//! tuning, the client/server identity rules, the bounded connect, and the
//! server's secret-key file. Relay configuration, the per-relay startup probe,
//! and the bind-and-come-online policy come from the shared crate.

use crate::error::{VpnError, VpnResult};
use crate::transport::build_quic_transport_config;
use crate::transport::path_selector::ExcludingPathSelector;
use crate::tunnel::signaling::VPN_ALPN;
use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use ipnet::IpNet;
use flexaccess_iroh::endpoint::{
    CreatedEndpoint, EndpointOptions, create_endpoint, endpoint_builder,
};
use iroh::{
    Endpoint, EndpointAddr, EndpointId, SecretKey,
    endpoint::{Builder as EndpointBuilder, Connection},
};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub use flexaccess_iroh::relay::RelayConfig;

/// Deadline for establishing the QUIC connection to the VPN server.
///
/// `Endpoint::connect` has no deadline of its own: when no path to the server is
/// reachable — or the underlying socket is wedged after a network change — that
/// future can pend forever, which would hang the CLI on first connect and stall
/// the reconnect loop permanently instead of retrying. Bounding it turns that
/// wedge into a normal recoverable `Signaling` error, so the reconnect loop backs
/// off and tries again (which also nudges the endpoint to rebind).
///
/// Generous: a healthy connect through address lookup + relay completes well
/// within this.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Connect to `addr` over [`VPN_ALPN`], bounded by [`CONNECT_TIMEOUT`].
///
/// Both the timeout and the underlying connect error map to
/// [`VpnError::Signaling`], which `is_recoverable()` treats as transient, so a
/// failure here feeds the client's reconnect loop rather than killing it. Shared
/// by the desktop/CLI client and the iOS session.
pub async fn connect_with_timeout(endpoint: &Endpoint, addr: EndpointAddr) -> VpnResult<Connection> {
    tokio::time::timeout(CONNECT_TIMEOUT, endpoint.connect(addr, VPN_ALPN))
        .await
        .map_err(|_| {
            VpnError::Signaling(format!(
                "Timed out connecting to server after {}s",
                CONNECT_TIMEOUT.as_secs()
            ))
        })?
        .map_err(|e| VpnError::Signaling(format!("Failed to connect to server: {e}")))
}

/// Load the server's secret key from its file (base64 encoded).
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

/// Load a secret key from a base64-encoded string.
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

/// The shared base builder with ezvpn's QUIC transport tuning. ezvpn runs no
/// mDNS (the shared crate's `mdns` feature is off), and never relay-only.
fn base_builder(relay_config: &RelayConfig, publish_address: bool) -> Result<EndpointBuilder> {
    Ok(endpoint_builder(
        relay_config,
        EndpointOptions {
            transport_config: build_quic_transport_config()?,
            publish_address,
            relay_only: false,
        },
    ))
}

/// A server endpoint builder: persistent identity (published on the default
/// relays) and the VPN ALPN.
fn server_builder(relay_config: &RelayConfig, secret: SecretKey) -> Result<EndpointBuilder> {
    Ok(base_builder(relay_config, true)?
        .alpns(vec![VPN_ALPN.to_vec()])
        .secret_key(secret))
}

/// Create the VPN server's iroh endpoint with its persistent identity.
///
/// A single endpoint serves both relay modes. With the default relays internet
/// discovery is on, so the server publishes its current home relay and clients
/// resolve it by endpoint ID (iroh's relay failover re-homes and republishes on
/// its own). With custom relays discovery is off, so clients reach the server
/// through the relay hints they attach to its `EndpointAddr` (see
/// `VpnClient::resolve_server_addr`). Every custom relay is probed (startup
/// fails only if none answers), the endpoint is bound without the relays that
/// failed and must come online. The relays left out come back in
/// [`CreatedEndpoint::relays_left_out`] for the home-relay failover
/// (`VpnServer::run`) to restore once they are connectable.
pub async fn create_server_endpoint(
    relay_config: &RelayConfig,
    secret: SecretKey,
) -> Result<CreatedEndpoint> {
    create_endpoint(relay_config, server_builder(relay_config, secret)?).await
}

/// Create a client endpoint: ephemeral identity, never published (the client
/// only dials out; its credential is the auth keypair, not the endpoint id).
/// Same relay probe and online wait as the server. A relay that failed the
/// probe stays out for the client's lifetime: it lives one session and runs
/// no failover.
///
/// A non-empty `exclude_direct_paths` installs [`ExcludingPathSelector`], so no
/// direct path to a server address in those networks carries the tunnel;
/// empty keeps iroh's default selector.
pub async fn create_client_endpoint(
    relay_config: &RelayConfig,
    exclude_direct_paths: &[IpNet],
) -> Result<Endpoint> {
    let mut builder = base_builder(relay_config, false)?;
    if !exclude_direct_paths.is_empty() {
        builder = builder.path_selector(Arc::new(ExcludingPathSelector::new(
            exclude_direct_paths.to_vec(),
        )));
    }
    let CreatedEndpoint { endpoint, .. } = create_endpoint(relay_config, builder).await?;
    Ok(endpoint)
}
