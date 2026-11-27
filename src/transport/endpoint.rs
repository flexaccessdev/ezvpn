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
use flexaccess_iroh::endpoint::{
    CreatedEndpoint, EndpointOptions, create_endpoint, endpoint_builder,
};
use ipnet::IpNet;
use iroh::{
    Endpoint, EndpointAddr, EndpointId, SecretKey,
    endpoint::{Builder as EndpointBuilder, Connection, Side},
};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

pub use flexaccess_iroh::endpoint::PendingCloses;
use flexaccess_iroh::endpoint::{ENDPOINT_CLOSE_TIMEOUT, close_endpoint};
pub use flexaccess_iroh::relay::{RelayConfig, RelayProbes};

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
pub async fn connect_with_timeout(
    endpoint: &Endpoint,
    addr: EndpointAddr,
) -> VpnResult<Connection> {
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

/// The shared base builder with ezvpn's QUIC transport tuning for `side`.
/// Only a server publishes its address. ezvpn runs no mDNS (the shared
/// crate's `mdns` feature is off), and never relay-only.
fn base_builder(relay_config: &RelayConfig, side: Side) -> Result<EndpointBuilder> {
    Ok(endpoint_builder(
        relay_config,
        EndpointOptions {
            transport_config: build_quic_transport_config(side)?,
            publish_address: side == Side::Server,
            relay_only: false,
        },
    ))
}

/// A server endpoint builder: persistent identity (published on the default
/// relays) and the VPN ALPN.
fn server_builder(relay_config: &RelayConfig, secret: SecretKey) -> Result<EndpointBuilder> {
    Ok(base_builder(relay_config, Side::Server)?
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
/// `VpnClient::resolve_server_addr`). The endpoint binds with every custom
/// relay and must come online, while each relay is probed beside it and taken
/// out of the relay map if it fails; startup fails only if none answers. The
/// startup probe comes back in [`CreatedEndpoint::relays`] for the home-relay
/// failover (`VpnServer::run`), which puts the relays it left out back once
/// they are connectable.
///
/// The probe can outlast the start: its task and probe endpoints, and any
/// close the creation stops waiting for, are kept in `closes` (see
/// [`close_and_finish`]).
pub async fn create_server_endpoint(
    relay_config: &RelayConfig,
    secret: SecretKey,
    closes: &PendingCloses,
) -> Result<CreatedEndpoint> {
    create_endpoint(relay_config, server_builder(relay_config, secret)?, closes).await
}

/// Create a client endpoint: ephemeral identity, never published (the client
/// only dials out; its credential is the auth keypair, not the endpoint id).
/// Same relay probe and online wait as the server, with `closes` as there. A
/// relay that failed the probe stays out for the client's lifetime: it lives
/// one session and runs no failover.
///
/// A non-empty `exclude_direct_paths` installs [`ExcludingPathSelector`], so no
/// direct path to a server address in those networks carries the tunnel;
/// empty keeps iroh's default selector.
pub async fn create_client_endpoint(
    relay_config: &RelayConfig,
    exclude_direct_paths: &[IpNet],
    closes: &PendingCloses,
) -> Result<Endpoint> {
    let mut builder = base_builder(relay_config, Side::Client)?;
    if !exclude_direct_paths.is_empty() {
        builder = builder.path_selector(Arc::new(ExcludingPathSelector::new(
            exclude_direct_paths.to_vec(),
        )));
    }
    let CreatedEndpoint { endpoint, .. } = create_endpoint(relay_config, builder, closes).await?;
    Ok(endpoint)
}

/// Close `endpoint` gracefully, then wait for what its creation left running
/// in `closes`: the startup relay probe, whose probe endpoints stay open for
/// up to 10 s after the start when a relay does not answer (the endpoint's
/// close stops the probe, which closes them), and any close the creation
/// stopped waiting for. A runtime that ended sooner would drop them without
/// `close()`. Neither close has a deadline of its own: the caller bounds the
/// whole.
pub async fn close_and_finish(endpoint: &Endpoint, closes: &PendingCloses) {
    endpoint.close().await;
    closes.finished().await;
}

/// Clean up after a start that failed, for a caller whose runtime ends with
/// it (the FFI sessions): close `endpoint` if it was created, then wait for
/// what is still closing in `closes` (see [`close_and_finish`]; a failed
/// creation leaves its own closes there too). Each of the two waits is
/// bounded by the shared crate's 5 s close timeout, so that the error is not
/// held back by a network that does not answer; what is slower is cut short
/// when the runtime goes.
pub async fn close_failed_start(endpoint: Option<Endpoint>, closes: &PendingCloses) {
    if let Some(endpoint) = endpoint {
        close_endpoint(endpoint, closes).await;
    }
    let _ = tokio::time::timeout(ENDPOINT_CLOSE_TIMEOUT, closes.finished()).await;
}
