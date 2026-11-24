//! Public-key authentication for ezvpn client connections.
//!
//! The transcript — sign the client's own ephemeral endpoint id, verify it
//! against the connection's TLS-authenticated `remote_id()` and the
//! authorized-keys file — is the shared [`flexaccess_iroh::auth`] one, and the
//! key format and files are
//! [flexaccess-keys](https://github.com/flexaccessdev/flexaccess-keys). This
//! module owns only what makes it ezvpn's: the domain-separation context, the
//! key-file loaders, and the authorization decision in the server's handshake
//! (`VpnServer::verify_client_auth`).
//!
//! ## Handshake
//! The client's iroh endpoint id stays ephemeral. In its [`VpnHandshake`] the
//! client sends its public key, its claimed endpoint id, and an ed25519
//! signature over that endpoint id (domain-separated). The server checks that
//! the claimed id equals the connection's TLS-authenticated `remote_id()`, that
//! the signature verifies under the presented public key, and that the key is
//! on the authorized-keys file — binding the credential to this connection so a
//! captured handshake cannot be replayed from another endpoint.
//!
//! Generate client keys with `flexaccess-keys generate-auth-key`.
//!
//! [`VpnHandshake`]: crate::tunnel::signaling::VpnHandshake

use anyhow::Result;
use flexaccess_keys::PublicKey;
use iroh::EndpointId;
use std::path::Path;

pub use flexaccess_iroh::auth::{AuthorizedKeys, ClientKey};

/// Domain-separation context prepended to the signed message, so an ezvpn
/// client-auth signature can never be confused with any other ed25519
/// signature made by the same key — including one made for another FlexAccess
/// application sharing the key format and transcript.
const AUTH_CONTEXT: &[u8] = b"ezvpn-client-auth-v1";

/// Sign the client-auth message binding `endpoint_id` (this client's own
/// ephemeral iroh id) under ezvpn's context, returning the base64url
/// signature.
pub fn sign_endpoint_id(key: &ClientKey, endpoint_id: &EndpointId) -> String {
    key.sign_endpoint_id(AUTH_CONTEXT, endpoint_id)
}

/// Verify a base64url client-auth signature over `endpoint_id` under `public`
/// and ezvpn's context.
pub fn verify_endpoint_id_signature(
    public: &PublicKey,
    endpoint_id: &EndpointId,
    signature_b64: &str,
) -> bool {
    flexaccess_iroh::auth::verify_endpoint_id_signature(
        public,
        AUTH_CONTEXT,
        endpoint_id,
        signature_b64,
    )
}

/// Load a client secret key from a shared-format key file (a bare
/// `ed25519-sec:...` token, or the token preceded by `#` header lines).
pub fn load_client_key_from_file(path: &Path) -> Result<ClientKey> {
    let private = flexaccess_keys::load_private_key(path).map_err(anyhow::Error::from)?;
    Ok(private.into())
}

/// Load the server's authorized client public keys (shared authorized-keys
/// document: one `ed25519-pub:...` per line, optional trailing comment, `#`
/// lines and blank lines ignored).
pub fn load_authorized_keys(path: &Path) -> Result<AuthorizedKeys> {
    flexaccess_keys::load_authorized_keys(path).map_err(anyhow::Error::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh::SecretKey;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn signature_is_bound_to_ezvpn_context() {
        let key = ClientKey::generate().unwrap();
        let id = SecretKey::generate().public();
        let sig = sign_endpoint_id(&key, &id);
        assert!(verify_endpoint_id_signature(&key.public_key(), &id, &sig));

        // The same key and id signed under another application's context
        // (flextunnel shares the key format and transcript) is not an ezvpn
        // credential.
        let foreign = key.sign_endpoint_id(b"flextunnel-client-auth-v1", &id);
        assert!(!verify_endpoint_id_signature(
            &key.public_key(),
            &id,
            &foreign
        ));
    }

    #[test]
    fn retired_auth_token_format_is_rejected() {
        // The pre-keypair ezvpn auth token is rejected, not migrated.
        assert!(
            ClientKey::from_secret_str("vmfNFxTPDKB3jsM1Q8kzAvZnQHbmJ1W49Rk8i1S2Jzrze9Q").is_err()
        );
    }

    #[test]
    fn shared_key_file_reloads() {
        let key = ClientKey::generate().unwrap();
        let contents = format!(
            "# Ed25519 authentication key\n# Public key: {} alice laptop\n{}\n",
            key.public_str(),
            key.secret_str()
        );
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(contents.as_bytes()).unwrap();
        let loaded = load_client_key_from_file(file.path()).unwrap();
        assert_eq!(loaded.public_str(), key.public_str());

        let mut bad = NamedTempFile::new().unwrap();
        writeln!(bad, "# only comments here").unwrap();
        assert!(load_client_key_from_file(bad.path()).is_err());
    }

    #[test]
    fn authorized_keys_file_parses_and_rejects_secrets() {
        let a = ClientKey::generate().unwrap();
        let b = ClientKey::generate().unwrap();
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# Authorized client keys\n\n{}", a.public_str()).unwrap();
        writeln!(file, "{} alice laptop", b.public_str()).unwrap();
        let keys = load_authorized_keys(file.path()).unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&a.public_key()));
        assert_eq!(keys.comment(&b.public_key()), Some("alice laptop"));

        // A secret key pasted into the authorized-keys file is rejected.
        let mut wrong = NamedTempFile::new().unwrap();
        writeln!(wrong, "{}", a.secret_str()).unwrap();
        assert!(load_authorized_keys(wrong.path()).is_err());
    }
}
