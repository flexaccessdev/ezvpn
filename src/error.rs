//! Error types for the VPN module.

use std::error::Error as StdError;
use std::num::NonZeroU32;
use thiserror::Error;

/// Boxed error type used for error chaining across crate boundaries.
pub type BoxError = Box<dyn StdError + Send + Sync + 'static>;

/// Context wrapper that preserves an optional underlying source error.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct ErrorContext {
    message: String,
    #[source]
    source: Option<BoxError>,
}

impl ErrorContext {
    /// Create context-only error (no underlying source).
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            source: None,
        }
    }

    /// Create context error with an underlying source.
    pub fn with_source<E>(message: impl Into<String>, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self {
            message: message.into(),
            source: Some(Box::new(source)),
        }
    }
}

/// VPN-specific errors.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum VpnError {
    /// TUN device creation failed.
    #[error("TUN device error: {0}")]
    TunDevice(#[source] ErrorContext),

    /// Network I/O error.
    #[error("Network error: {0}")]
    Network(#[from] std::io::Error),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(#[source] ErrorContext),

    /// Signaling/iroh error (transient, e.g., connection failed).
    #[error("Signaling error: {0}")]
    Signaling(String),

    /// Authentication failed (permanent, e.g., invalid token, server rejected).
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),

    /// IP address assignment error.
    #[error("IP assignment error: {0}")]
    IpAssignment(String),

    /// Connection lost during VPN session (recoverable via reconnect).
    #[error("Connection lost: {0}")]
    ConnectionLost(String),

    /// Maximum reconnection attempts exceeded.
    #[error("Max reconnection attempts ({0}) exceeded")]
    MaxReconnectAttemptsExceeded(NonZeroU32),

    /// Server's VPN network configuration changed across a reconnect.
    #[error("Server VPN configuration changed: {0}")]
    ServerConfigChanged(String),
}

impl VpnError {
    /// Create a TUN device error with context only.
    pub fn tun_device(message: impl Into<String>) -> Self {
        Self::TunDevice(ErrorContext::new(message))
    }

    /// Create a TUN device error with preserved source.
    pub fn tun_device_with_source<E>(message: impl Into<String>, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::TunDevice(ErrorContext::with_source(message, source))
    }

    /// Create a configuration error with context only.
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config(ErrorContext::new(message))
    }

    /// Create a configuration error with preserved source.
    pub fn config_with_source<E>(message: impl Into<String>, source: E) -> Self
    where
        E: StdError + Send + Sync + 'static,
    {
        Self::Config(ErrorContext::with_source(message, source))
    }

    /// Returns true if this error is potentially recoverable via reconnection.
    ///
    /// **Recoverable (transient):**
    /// - `ConnectionLost` - VPN session ended (server restart, network blip)
    /// - `Network` - I/O errors (connection reset, timeout)
    /// - `Signaling` - iroh connection issues (peer unreachable, relay failure)
    ///
    /// **Non-recoverable (permanent):**
    /// - `AuthenticationFailed` - invalid token, server rejected credentials
    /// - `Config` - invalid configuration (won't change without user action)
    /// - `TunDevice` - permission denied, device creation failed
    /// - `IpAssignment` - IP pool exhausted (unlikely to recover quickly)
    /// - `MaxReconnectAttemptsExceeded` - retry limit hit
    /// - `ServerConfigChanged` - server's VPN network/gateway differs from
    ///   the established session; reconfiguring would mean inconsistent routing/
    ///   TUN state, so we quit instead. (A change to just the assigned client
    ///   IP is not fatal — it rebuilds in place; see `check_config_consistency`.)
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            VpnError::ConnectionLost(_) | VpnError::Network(_) | VpnError::Signaling(_)
        )
    }
}

/// Result type alias for VPN operations.
pub type VpnResult<T> = Result<T, VpnError>;
