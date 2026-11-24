//! Key, connection-path and event-callback helpers shared by the platform FFI
//! surfaces ([`crate::ffi`] for Apple, [`crate::ffi_windows`] for Windows).
//!
//! Both GUI apps generate and inspect client keys themselves (they have no
//! `flexaccess-keys` CLI to hand the user), and the two FFI modules compile for
//! disjoint targets — so the logic lives here once instead of being copied into
//! each and left to drift.
//!
//! Errors are returned as ready-to-write messages: every caller does nothing
//! with them but copy them into the caller's output buffer.

use std::ffi::{CString, c_char, c_int, c_void};
use std::sync::Mutex;

use crate::auth::ClientKey;
use crate::transport::paths::{ConnPathKind, ConnectionSnapshot};

/// C event callback both FFI surfaces take (`ezvpn_run` on Apple,
/// `ezvpn_start` on Windows): `ctx` is the caller's pointer, passed back
/// verbatim; `event` is one of that surface's `EZVPN_EVENT_*` codes; `message`
/// is NUL-terminated and valid only for the duration of the call, or null.
pub type EzvpnEventCallback = extern "C" fn(ctx: *mut c_void, event: c_int, message: *const c_char);

/// The caller's callback and opaque `ctx`, moved onto the threads that report
/// events. The caller guarantees `ctx` stays valid until its `ezvpn_stop`.
#[derive(Clone, Copy)]
pub struct EventTarget {
    pub callback: EzvpnEventCallback,
    pub ctx: *mut c_void,
}
// SAFETY: the pointer is never dereferenced here, only handed back to the
// caller's callback, whose contract covers calls from any thread.
unsafe impl Send for EventTarget {}
unsafe impl Sync for EventTarget {}

impl EventTarget {
    pub fn emit(self, event: c_int, message: Option<&str>) {
        match message {
            None => (self.callback)(self.ctx, event, std::ptr::null()),
            Some(m) => {
                // Our messages carry no interior NUL; fall back rather than drop
                // the event if one ever does.
                let msg = CString::new(m).unwrap_or_else(|_| CString::from(c"(unprintable)"));
                (self.callback)(self.ctx, event, msg.as_ptr());
            }
        }
    }
}

/// Lock an FFI handle's stop flag, recovering it from a callback that panicked
/// (the flag itself is always valid). Event callbacks run under this lock and
/// skip once the flag is set, so `ezvpn_stop` (which sets it) waits out a
/// callback in flight and none runs after it.
pub fn lock_ignoring_poison(stopped: &Mutex<bool>) -> std::sync::MutexGuard<'_, bool> {
    stopped
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Generate a fresh client keypair and render the key document both FFI
/// surfaces hand back:
/// `{"created":"<UTC>","public_key":"ed25519-pub:...","secret_key":"ed25519-sec:..."}`
///
/// The only failure is an unavailable system RNG.
pub fn generate_client_key_json() -> Result<String, String> {
    let key = ClientKey::generate().map_err(|e| format!("{e:#}"))?;
    Ok(serde_json::json!({
        "created": flexaccess_keys::rfc3339_utc(std::time::SystemTime::now()),
        "public_key": key.public_str(),
        "secret_key": key.secret_str(),
    })
    .to_string())
}

/// Derive the public key (`ed25519-pub:...`) of a stored secret key, so an app
/// can display it without persisting it separately.
pub fn client_public_key(secret: &str) -> Result<String, String> {
    ClientKey::from_secret_str(secret.trim())
        .map(|key| key.public_str())
        .map_err(|e| format!("invalid secret key: {e:#}"))
}

/// Render the connection-path document both FFI surfaces hand back
/// (`ezvpn_conn_path`): every path with its kind (`"direct"`, `"relay"`, or
/// `"other"`), display line and whether iroh routes over it right now, plus
/// the custom-relay health. `None` (disconnected) renders empty arrays.
pub fn conn_path_json(snapshot: Option<ConnectionSnapshot>) -> String {
    let (paths, custom_relays) = match snapshot {
        Some(s) => (s.paths, s.custom_relays),
        None => (Vec::new(), Vec::new()),
    };
    let paths: Vec<_> = paths
        .into_iter()
        .map(|p| {
            let kind = match p.kind {
                ConnPathKind::Direct => "direct",
                ConnPathKind::Relay => "relay",
                ConnPathKind::Other => "other",
            };
            serde_json::json!({ "kind": kind, "display": p.display, "selected": p.selected })
        })
        .collect();
    serde_json::json!({ "paths": paths, "custom_relays": custom_relays }).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::paths::{ConnPath, CustomRelayStatus};

    #[test]
    fn conn_path_document_shape() {
        let json = conn_path_json(Some(ConnectionSnapshot {
            description: String::new(),
            paths: vec![
                ConnPath {
                    kind: ConnPathKind::Direct,
                    display: "Direct 10.0.0.1:4000 (rtt 1ms)".into(),
                    selected: true,
                },
                ConnPath {
                    kind: ConnPathKind::Relay,
                    display: "Relay https://relay.example/ (rtt 40ms)".into(),
                    selected: false,
                },
            ],
            custom_relays: vec![CustomRelayStatus {
                url: "https://relay.example/".into(),
                working: Some(false),
                error: Some("timeout".into()),
            }],
        }));
        let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(doc["paths"][0]["kind"], "direct");
        assert_eq!(doc["paths"][0]["selected"], true);
        assert_eq!(doc["paths"][1]["kind"], "relay");
        assert_eq!(doc["custom_relays"][0]["working"], false);
        assert_eq!(doc["custom_relays"][0]["error"], "timeout");

        let empty: serde_json::Value = serde_json::from_str(&conn_path_json(None)).unwrap();
        assert_eq!(
            empty,
            serde_json::json!({ "paths": [], "custom_relays": [] })
        );
    }

    #[test]
    fn generated_document_round_trips() {
        let json = generate_client_key_json().unwrap();
        let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
        let secret = doc["secret_key"].as_str().unwrap();
        let public = doc["public_key"].as_str().unwrap();
        assert!(doc["created"].as_str().is_some_and(|c| !c.is_empty()));
        // The advertised public key is the one the secret actually derives.
        assert_eq!(client_public_key(secret).unwrap(), public);
    }

    #[test]
    fn public_key_tolerates_whitespace_and_rejects_garbage() {
        let json = generate_client_key_json().unwrap();
        let doc: serde_json::Value = serde_json::from_str(&json).unwrap();
        let secret = doc["secret_key"].as_str().unwrap();
        assert_eq!(
            client_public_key(&format!("  {secret}\n")).unwrap(),
            doc["public_key"].as_str().unwrap()
        );
        let err = client_public_key("not-a-key").unwrap_err();
        assert!(err.contains("invalid secret key"), "{err}");
    }
}
