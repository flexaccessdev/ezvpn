//! JNI surface for the Android app (`ezvpn-android`).
//!
//! Android has no C-callable app boundary: Kotlin reaches native code only
//! through JNI, so this module exposes the fd-based lifecycle of [`crate::ffi`]
//! as the `external fun`s of one Kotlin object, `dev.flexaccess.ezvpn.EzvpnNative`
//! (the JNI symbol names below encode that class; renaming it on either side
//! breaks the link at load time). It adds nothing of its own: every entry point
//! converts Java strings, delegates to the shared [`EzvpnHandle`] methods, and
//! converts the result back. The JSON config/result shapes are exactly the ones
//! documented in `ios/ezvpn.h` and [`crate::ffi`].
//!
//! The `VpnService` plays the role the `NEPacketTunnelProvider` plays on Apple
//! platforms: it owns the tun interface, addresses, routes, and MTU
//! (`VpnService.Builder`), calls `connect` first to learn the assigned
//! addresses and bypass set, `establish()`es the interface, then hands the fd
//! to `run`. One Android-specific addition: `run` takes no callback argument,
//! but when the data loop ends on its own (peer close, idle timeout, fatal I/O
//! error) the library calls back into Kotlin —
//! `EzvpnNative.onTunnelExit(handle: Long, error: String?)` — so the service
//! can tear the interface down; a `stop` never triggers that callback.
//!
//! Handles cross the boundary as `jlong` (the raw `*mut EzvpnHandle`); `0` is
//! null. As with the C API, the Kotlin side must call `stop` exactly once per
//! successful `connect` and never use a handle after it.
//!
//! Never unwinds into the JVM: the release profile is `panic = "abort"`, so a
//! panic terminates the app process instead.

use std::ffi::{c_int, c_void};
use std::sync::OnceLock;

use jni::JNIEnv;
use jni::objects::{GlobalRef, JClass, JObject, JObjectArray, JString, JValue};
use jni::sys::{jint, jlong, jstring};

use crate::ffi::{EzvpnHandle, connect_inner, ezvpn_init_logging};

/// Set once `EzvpnNative.init` has registered the app context; later calls
/// are no-ops (ndk-context aborts on a second registration).
static ANDROID_CONTEXT: OnceLock<()> = OnceLock::new();

/// The JVM and a global ref to the `EzvpnNative` class, captured by `init` for
/// the exit callback. Process-lifetime statics (the class never unloads), so
/// the hook closure owns no JNI references of its own — dropping a `GlobalRef`
/// on a runtime thread that is not attached to the JVM would cost an
/// attach/detach round trip per session.
static JVM: OnceLock<(jni::JavaVM, GlobalRef)> = OnceLock::new();

/// `EzvpnNative.init(context: Context)`: one-time process setup, to be called
/// from `Application.onCreate` before anything else. Routes `log` output to
/// logcat (tag `ezvpn`) and registers the JVM + application context with
/// `ndk-context`, which iroh's dependencies (hickory-resolver's system DNS
/// lookup, netwatch's interface enumeration) use to reach
/// `ConnectivityManager` through JNI — without it the first connect aborts
/// the process with "android context was not initialized". Idempotent.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_ezvpn_EzvpnNative_init<'local>(
    env: JNIEnv<'local>,
    class: JClass<'local>,
    context: JObject<'local>,
) {
    ezvpn_init_logging();
    if ANDROID_CONTEXT.get().is_some() {
        return;
    }
    let (vm, context_ref, class_ref) =
        match (env.get_java_vm(), env.new_global_ref(&context), env.new_global_ref(&class)) {
            (Ok(vm), Ok(context_ref), Ok(class_ref)) => (vm, context_ref, class_ref),
            (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => {
                log::error!("ezvpn init: cannot capture the JVM/context/class: {e}");
                return;
            }
        };
    let vm_ptr = vm.get_java_vm_pointer().cast::<c_void>();
    let context_ptr = context_ref.as_obj().as_raw().cast::<c_void>();
    // The global ref must outlive every later JNI call through ndk-context,
    // i.e. the process: leak it on purpose.
    std::mem::forget(context_ref);
    // SAFETY: both pointers are valid for the life of the process (the JVM
    // pointer by construction, the context through the leaked global ref), and
    // the OnceLock guarantees a single registration.
    unsafe { ndk_context::initialize_android_context(vm_ptr, context_ptr) };
    let _ = JVM.set((vm, class_ref));
    let _ = ANDROID_CONTEXT.set(());
}

/// `EzvpnNative.generateClientKey(): String`: the
/// `{"created":…,"public_key":…,"secret_key":…}` document. Throws
/// `RuntimeException` (and returns null) if the system RNG was unavailable.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_ezvpn_EzvpnNative_generateClientKey<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jstring {
    match crate::ffi_common::generate_client_key_json() {
        Ok(json) => new_jstring(&mut env, &json),
        Err(msg) => {
            throw(&mut env, &msg);
            std::ptr::null_mut()
        }
    }
}

/// `EzvpnNative.clientPublicKey(secret: String): String?`: the `ed25519-pub:…`
/// half of a secret key, or null when the secret does not parse — which also
/// makes this the validator for pasted keys.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_ezvpn_EzvpnNative_clientPublicKey<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    secret: JString<'local>,
) -> jstring {
    let Some(secret) = get_string(&mut env, &secret) else {
        return std::ptr::null_mut();
    };
    match crate::ffi_common::client_public_key(&secret) {
        Ok(public) => new_jstring(&mut env, &public),
        Err(_) => std::ptr::null_mut(),
    }
}

/// `EzvpnNative.connect(configJson: String, out: Array<String?>): Long`:
/// connect + handshake (blocks for the duration, bounded by the core's connect
/// timeout — call it off the main thread). Returns the handle and stores the
/// network-config JSON in `out[0]`; on failure returns `0` and stores the error
/// message in `out[0]` instead.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_ezvpn_EzvpnNative_connect<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    config_json: JString<'local>,
    out: JObjectArray<'local>,
) -> jlong {
    let Some(json) = get_string(&mut env, &config_json) else {
        set_out(&mut env, &out, "config_json is not a valid string");
        return 0;
    };
    match connect_inner(&json) {
        Ok((handle, result_json)) => {
            set_out(&mut env, &out, &result_json);
            Box::into_raw(Box::new(handle)) as jlong
        }
        Err(msg) => {
            set_out(&mut env, &out, &msg);
            0
        }
    }
}

/// `EzvpnNative.run(handle: Long, tunFd: Int): Int`: start the data loop on
/// the fd from `VpnService.Builder.establish()`. Returns `0` on success, `-1`
/// on error (null handle, no pending session, dup failure). The fd is `dup`ed
/// before this returns, so the caller may close its `ParcelFileDescriptor`
/// right after. When the loop later ends on its own, the library calls
/// `EzvpnNative.onTunnelExit(handle, error)` on a background thread; `error`
/// is null for a clean end. The callback carries the same handle value so the
/// Kotlin side can ignore a stale one.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_ezvpn_EzvpnNative_run<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    tun_fd: jint,
) -> jint {
    let Some(handle_ref) = handle_mut(handle) else {
        return -1;
    };
    // The exit hook runs on a tokio worker thread, which must attach to the JVM
    // and must reach the class through a global ref: `FindClass` from a
    // native-spawned thread uses the system class loader, which cannot see app
    // classes. Both were captured by `init`.
    if JVM.get().is_none() {
        log::error!("ezvpn run: EzvpnNative.init was not called");
        return -1;
    }
    // No reconnect events: the Kotlin service tears down on exit and runs its
    // own policy, so the in-place reconnect loop stays off here.
    let hook = Box::new(move |result: &crate::error::VpnResult<()>| {
        if let Some((vm, class_ref)) = JVM.get() {
            let result = result.as_ref().map(|_| ()).map_err(|e| e.to_string());
            notify_tunnel_exit(vm, class_ref, handle, result);
        }
    });
    match handle_ref.run(tun_fd as c_int, Some(hook), None) {
        Ok(()) => 0,
        Err(e) => {
            log::error!("ezvpn run: {e}");
            -1
        }
    }
}

/// Deliver the end-of-loop notification to `EzvpnNative.onTunnelExit`.
fn notify_tunnel_exit(vm: &jni::JavaVM, class: &GlobalRef, handle: jlong, result: Result<(), String>) {
    match &result {
        Ok(()) => log::info!("tunnel loop ended"),
        Err(e) => log::warn!("tunnel loop ended with error: {e}"),
    }
    let mut env = match vm.attach_current_thread() {
        Ok(env) => env,
        Err(e) => {
            log::error!("cannot attach tunnel thread to the JVM for onTunnelExit: {e}");
            return;
        }
    };
    let error = match &result {
        Ok(()) => JString::default(),
        Err(msg) => match env.new_string(msg) {
            Ok(s) => s,
            Err(e) => {
                log::error!("cannot build onTunnelExit message: {e}");
                JString::default()
            }
        },
    };
    if let Err(e) = env.call_static_method(
        class,
        "onTunnelExit",
        "(JLjava/lang/String;)V",
        &[JValue::Long(handle), JValue::Object(&error)],
    ) {
        log::error!("onTunnelExit callback failed: {e}");
        // A pending Java exception would abort the next JNI call on this
        // thread; clear it since the thread is about to detach anyway.
        let _ = env.exception_clear();
    }
}

/// `EzvpnNative.connPath(handle: Long): String?`: the `ezvpn_conn_path` JSON
/// snapshot (paths + custom-relay health), or null for a null handle.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_ezvpn_EzvpnNative_connPath<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jstring {
    let Some(handle_ref) = handle_ref(handle) else {
        return std::ptr::null_mut();
    };
    let json = handle_ref.conn_path_json();
    new_jstring(&mut env, &json)
}

/// `EzvpnNative.stop(handle: Long)`: abort the loop, close the endpoint, free
/// the handle. `0` is a no-op; the handle is invalid afterwards.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_flexaccess_ezvpn_EzvpnNative_stop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) {
    if handle == 0 {
        return;
    }
    // SAFETY: the Kotlin side passes back a value obtained from `connect` and
    // never reuses it after `stop` (see the module docs for the contract).
    unsafe { Box::from_raw(handle as *mut EzvpnHandle) }.stop();
}

// ---------------------------------------------------------------------------
// JNI helpers

/// Borrow the handle behind a `jlong`, or `None` for `0`.
fn handle_ref<'a>(handle: jlong) -> Option<&'a EzvpnHandle> {
    if handle == 0 {
        return None;
    }
    // SAFETY: see `Java_…_stop`; a non-zero value is a live handle from `connect`.
    Some(unsafe { &*(handle as *const EzvpnHandle) })
}

fn handle_mut<'a>(handle: jlong) -> Option<&'a mut EzvpnHandle> {
    if handle == 0 {
        return None;
    }
    // SAFETY: as above; the Kotlin side serializes calls on one handle.
    Some(unsafe { &mut *(handle as *mut EzvpnHandle) })
}

/// Copy a Java string out, or `None` for null / non-UTF-8 input.
fn get_string(env: &mut JNIEnv, s: &JString) -> Option<String> {
    if s.is_null() {
        return None;
    }
    env.get_string(s).ok().map(|js| js.into())
}

/// Build a Java string, or null (with a pending `OutOfMemoryError`) when the
/// JVM could not allocate it.
fn new_jstring(env: &mut JNIEnv, s: &str) -> jstring {
    env.new_string(s)
        .map(|js| js.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// Store `value` in `out[0]`. Failures (null array, zero length) are logged:
/// the caller already reports success/failure through its return value.
fn set_out(env: &mut JNIEnv, out: &JObjectArray, value: &str) {
    let Ok(js) = env.new_string(value) else {
        log::error!("cannot build JNI out string");
        return;
    };
    if let Err(e) = env.set_object_array_element(out, 0, &js) {
        log::error!("cannot store JNI out string: {e}");
        let _ = env.exception_clear();
    }
}

fn throw(env: &mut JNIEnv, msg: &str) {
    if let Err(e) = env.throw_new("java/lang/RuntimeException", msg) {
        log::error!("cannot throw RuntimeException({msg}): {e}");
    }
}
