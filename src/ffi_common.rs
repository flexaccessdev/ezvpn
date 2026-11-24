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

/// Write `s` (always NUL-terminated) into the caller buffer. Returns `true` if
/// the full string fit, `false` if it was truncated or the buffer was unusable.
///
/// # Safety
/// Unless `buf` is null or `len` is 0 (then nothing is written), `buf` must be
/// valid for writes of `len` bytes, and those bytes must not overlap `s`. The
/// FFI exports pass on their own `out_buf`/`out_len` contract.
#[cfg(any(test, target_os = "ios", target_os = "macos", target_os = "windows"))]
pub(crate) unsafe fn write_cstr(buf: *mut c_char, len: usize, s: &str) -> bool {
    if buf.is_null() || len == 0 {
        return false;
    }
    let bytes = s.as_bytes();
    // Reserve one byte for the trailing NUL.
    let copy = bytes.len().min(len - 1);
    unsafe {
        std::ptr::copy_nonoverlapping(bytes.as_ptr(), buf.cast::<u8>(), copy);
        *buf.add(copy) = 0;
    }
    copy == bytes.len()
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

/// Test helpers for the FFI surfaces, written from the C caller's side.
#[cfg(test)]
pub(crate) mod test_support {
    use std::ffi::{CStr, c_char};

    /// The NUL-terminated string at the start of `buf`; panics if `buf` holds no
    /// NUL, which reads only inside the buffer (unlike `CStr::from_ptr`).
    pub fn cstr(buf: &[c_char]) -> &str {
        // SAFETY: `c_char` and `u8` have the same size and alignment.
        let bytes = unsafe { std::slice::from_raw_parts(buf.as_ptr().cast::<u8>(), buf.len()) };
        CStr::from_bytes_until_nul(bytes)
            .expect("no NUL inside the buffer")
            .to_str()
            .expect("not UTF-8")
    }

    /// Drive one FFI surface's exported key functions through their buffer
    /// contracts: a buffer of exactly the right size, one byte short, room for
    /// only the NUL, none at all, and refused secrets. Each buffer is allocated
    /// at exactly the length passed, so under Miri a write past `out_len` (or a
    /// read past the secret's NUL) is reported as undefined behavior.
    #[cfg(any(target_os = "ios", target_os = "macos", target_os = "windows"))]
    pub fn check_key_exports(
        generate: unsafe extern "C" fn(*mut c_char, usize) -> std::ffi::c_int,
        public_key: unsafe extern "C" fn(*const c_char, *mut c_char, usize) -> std::ffi::c_int,
    ) {
        use std::ffi::CString;
        const FILL: c_char = 0x55;

        let mut doc = vec![FILL; 512];
        assert_eq!(unsafe { generate(doc.as_mut_ptr(), doc.len()) }, 1);
        let doc: serde_json::Value = serde_json::from_str(cstr(&doc)).unwrap();
        let secret = CString::new(doc["secret_key"].as_str().unwrap()).unwrap();
        let public = doc["public_key"].as_str().unwrap();

        let mut exact = vec![FILL; public.len() + 1];
        assert_eq!(
            unsafe { public_key(secret.as_ptr(), exact.as_mut_ptr(), exact.len()) },
            1
        );
        assert_eq!(cstr(&exact), public);

        // One byte short: truncated, and the NUL still lands inside.
        let mut short = vec![FILL; public.len()];
        assert_eq!(
            unsafe { public_key(secret.as_ptr(), short.as_mut_ptr(), short.len()) },
            0
        );
        assert_eq!(cstr(&short), &public[..public.len() - 1]);

        let mut nul_only = vec![FILL; 1];
        assert_eq!(
            unsafe { generate(nul_only.as_mut_ptr(), nul_only.len()) },
            0
        );
        assert_eq!(nul_only[0], 0);
        assert_eq!(unsafe { generate(std::ptr::null_mut(), 0) }, 0);
        assert_eq!(
            unsafe { public_key(secret.as_ptr(), std::ptr::null_mut(), 0) },
            0
        );

        let mut err = vec![FILL; 128];
        assert_eq!(
            unsafe { public_key(std::ptr::null(), err.as_mut_ptr(), err.len()) },
            0
        );
        assert_eq!(cstr(&err), "secret_key is null");
        let not_utf8 = [0xffu8 as c_char, 0];
        assert_eq!(
            unsafe { public_key(not_utf8.as_ptr(), err.as_mut_ptr(), err.len()) },
            0
        );
        assert_eq!(cstr(&err), "secret_key is not valid UTF-8");
        assert_eq!(
            unsafe { public_key(c"not-a-key".as_ptr(), err.as_mut_ptr(), err.len()) },
            0
        );
        assert!(
            cstr(&err).starts_with("invalid secret key"),
            "{}",
            cstr(&err)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::cstr;
    use super::*;
    use crate::transport::paths::{ConnPath, CustomRelayStatus};
    use std::ffi::CStr;

    // Every buffer below is allocated at exactly the length passed, so under
    // Miri a write past it is reported rather than landing in spare capacity.
    #[test]
    fn write_cstr_stays_inside_the_buffer() {
        const FILL: c_char = 0x55;

        let mut exact = vec![FILL; 7];
        assert!(unsafe { write_cstr(exact.as_mut_ptr(), exact.len(), "abcdef") });
        assert_eq!(cstr(&exact), "abcdef");

        let mut short = vec![FILL; 7];
        assert!(!unsafe { write_cstr(short.as_mut_ptr(), short.len(), "abcdefg") });
        assert_eq!(cstr(&short), "abcdef");

        let mut nul_only = vec![FILL; 1];
        assert!(!unsafe { write_cstr(nul_only.as_mut_ptr(), nul_only.len(), "abc") });
        assert_eq!(nul_only[0], 0);
        assert!(unsafe { write_cstr(nul_only.as_mut_ptr(), nul_only.len(), "") });

        // Unusable buffers are left alone.
        let mut untouched = vec![FILL; 4];
        assert!(!unsafe { write_cstr(untouched.as_mut_ptr(), 0, "abc") });
        assert_eq!(untouched, vec![FILL; 4]);
        assert!(!unsafe { write_cstr(std::ptr::null_mut(), 8, "abc") });
    }

    type Seen = Mutex<Vec<(c_int, Option<String>)>>;

    extern "C" fn record(ctx: *mut c_void, event: c_int, message: *const c_char) {
        // SAFETY: the test below passes a `Seen` that outlives every emit.
        let seen = unsafe { &*ctx.cast::<Seen>() };
        let message = (!message.is_null()).then(|| {
            unsafe { CStr::from_ptr(message) }
                .to_str()
                .unwrap()
                .to_owned()
        });
        seen.lock().unwrap().push((event, message));
    }

    #[test]
    fn event_target_hands_back_ctx_and_message() {
        let seen: Seen = Mutex::new(Vec::new());
        let target = EventTarget {
            callback: record,
            ctx: (&raw const seen).cast_mut().cast(),
        };
        target.emit(1, None);
        target.emit(2, Some("connected"));
        target.emit(3, Some("bad\0nul"));
        // The run loop reports from its own thread.
        std::thread::scope(|s| {
            s.spawn(move || target.emit(4, Some("from worker")));
        });
        assert_eq!(
            seen.into_inner().unwrap(),
            vec![
                (1, None),
                (2, Some("connected".to_owned())),
                (3, Some("(unprintable)".to_owned())),
                (4, Some("from worker".to_owned())),
            ]
        );
    }

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
