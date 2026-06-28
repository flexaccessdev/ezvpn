//! Runtime filesystem layout and single-instance locking.
//!
//! Owns the per-platform locations `ezvpn` uses at runtime — the ephemeral
//! runtime directory ([`runtime_dir`], for lock files and control sockets) and
//! the persistent log directory ([`log_dir`]) — plus instance-name validation
//! and the file-based single-instance lock ([`VpnLock`]).
//!
//! The lock ensures only one VPN instance runs at a time per (role, instance
//! name) to prevent routing conflicts and TUN device issues. The client and
//! server use separate lock files, so a client and a server can run
//! simultaneously on the same host. Clients are additionally scoped by an
//! instance name (default `default`), so multiple clients with distinct
//! instance names can coexist.
//!
//! # Platform Support
//!
//! This module supports Linux, macOS, and Windows.

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("VPN runtime support is only available on Linux, macOS, and Windows");

use crate::error::{VpnError, VpnResult};
use std::ffi::OsStr;
use std::fs::{File, OpenOptions, TryLockError};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Directory for runtime files (lock files and control sockets).
///
/// A **fixed, machine-global, root-owned** directory per platform — `ezvpn`
/// runs as root (the tunnel creates a TUN device and edits the routing table),
/// so a per-host location is reachable by every subcommand and resolves to the
/// same place no matter how the process was started, so `status`/`stop` always
/// find the running instance.
///
/// Holds only ephemeral runtime state — `/run` is tmpfs and cleared on reboot.
/// Persistent files such as the daemon log live in [`log_dir`] instead.
///
/// Defaults: `/run/ezvpn` on Linux, `/var/run/ezvpn` on macOS, and
/// `%ProgramData%\ezvpn` on Windows (lock files only; control sockets there
/// are named pipes in a global namespace).
/// Override with the `EZVPN_RUNTIME_DIR` environment variable (e.g. for
/// containers, tests, or a rootless deployment); it must be an absolute path
/// (validated at startup by [`validate_dir_env`]).
#[cfg(not(test))]
pub(crate) fn runtime_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("EZVPN_RUNTIME_DIR")
        && !dir.is_empty()
    {
        return PathBuf::from(dir);
    }
    platform_runtime_dir()
}

/// Test build: isolate to a writable per-process temp dir so the suite needs
/// neither root nor a real `/run`.
#[cfg(test)]
pub(crate) fn runtime_dir() -> PathBuf {
    use std::sync::OnceLock;
    static TEST_DIR: OnceLock<PathBuf> = OnceLock::new();
    TEST_DIR
        .get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("ezvpn-test-{}", std::process::id()));
            let _ = std::fs::create_dir_all(&dir);
            dir
        })
        .clone()
}

/// Fixed per-platform runtime directory (used when `EZVPN_RUNTIME_DIR` is
/// unset). Not compiled into test builds, where [`runtime_dir`] isolates to a
/// temp dir instead.
#[cfg(all(not(test), target_os = "linux"))]
fn platform_runtime_dir() -> PathBuf {
    // /run is the FHS-canonical runtime location (tmpfs, present on every
    // modern Linux); /var/run is just a deprecated symlink to it.
    PathBuf::from("/run/ezvpn")
}

#[cfg(all(not(test), target_os = "macos"))]
fn platform_runtime_dir() -> PathBuf {
    PathBuf::from("/var/run/ezvpn")
}

#[cfg(all(not(test), target_os = "windows"))]
fn platform_runtime_dir() -> PathBuf {
    program_data_dir().join("ezvpn")
}

/// Directory for the daemon log file.
///
/// Kept separate from [`runtime_dir`]: logs are persistent diagnostic output
/// and belong in the system log location, not on the tmpfs runtime dir (which
/// is cleared on reboot). The path is absolute so it survives the daemon's
/// `chdir("/")`.
///
/// Defaults: `/var/log/ezvpn` on Linux and macOS, and `%ProgramData%\ezvpn\logs`
/// on Windows. Override with the `EZVPN_LOG_DIR` environment variable; it must
/// be an absolute path (validated at startup by [`validate_dir_env`]).
#[cfg(not(test))]
pub(crate) fn log_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("EZVPN_LOG_DIR")
        && !dir.is_empty()
    {
        return PathBuf::from(dir);
    }
    platform_log_dir()
}

/// Test build: reuse the isolated per-process temp dir so the suite neither
/// touches a real `/var/log` nor needs root.
#[cfg(test)]
pub(crate) fn log_dir() -> PathBuf {
    runtime_dir()
}

#[cfg(all(not(test), any(target_os = "linux", target_os = "macos")))]
fn platform_log_dir() -> PathBuf {
    PathBuf::from("/var/log/ezvpn")
}

#[cfg(all(not(test), target_os = "windows"))]
fn platform_log_dir() -> PathBuf {
    program_data_dir().join("ezvpn").join("logs")
}

/// Machine-global `ProgramData` base directory (Windows).
///
/// `ProgramData` is shared by all users (not a per-user profile location),
/// which is what a LocalSystem service wants. Resolution order:
///   1. the `%ProgramData%` env var (the documented override, present on every
///      normal install and already pointing at the real install drive), then
///   2. the Known Folders API (`SHGetKnownFolderPath(FOLDERID_ProgramData)`),
///      which is authoritative in stripped service environments where the env
///      var may be absent — and, like the env var, follows the actual install
///      drive instead of assuming `C:\`.
///
/// The final `C:\ProgramData` literal is a last-ditch fallback only reached if
/// both the env var is unset *and* the shell32 call fails.
#[cfg(all(not(test), target_os = "windows"))]
fn program_data_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("ProgramData").filter(|s| !s.is_empty()) {
        return PathBuf::from(dir);
    }
    known_folders::get_known_folder_path(known_folders::KnownFolder::ProgramData)
        .unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"))
}

/// System-wide configuration directory — the default location for the
/// server/client TOML config files when neither `-c` nor `--default-config`'s
/// explicit path is given.
///
/// Machine-global on every platform (not a per-user home directory): `ezvpn`
/// runs as root/LocalSystem, so its config belongs in the system location where
/// every subcommand resolves the same place regardless of which user invokes it.
///
/// Defaults: `/etc/ezvpn` on Linux, `/usr/local/etc/ezvpn` on macOS, and
/// `%ProgramData%\ezvpn` on Windows.
#[cfg(not(test))]
pub(crate) fn config_dir() -> PathBuf {
    platform_config_dir()
}

/// Test build: isolate to the same writable per-process temp dir as the other
/// path helpers so the suite neither reads a real `/etc` nor needs root.
#[cfg(test)]
pub(crate) fn config_dir() -> PathBuf {
    runtime_dir()
}

#[cfg(all(not(test), target_os = "linux"))]
fn platform_config_dir() -> PathBuf {
    PathBuf::from("/etc/ezvpn")
}

#[cfg(all(not(test), target_os = "macos"))]
fn platform_config_dir() -> PathBuf {
    PathBuf::from("/usr/local/etc/ezvpn")
}

#[cfg(all(not(test), target_os = "windows"))]
fn platform_config_dir() -> PathBuf {
    program_data_dir().join("ezvpn")
}

/// Names of the directory-override environment variables, checked by
/// [`validate_dir_env`].
const DIR_ENV_VARS: [&str; 2] = ["EZVPN_RUNTIME_DIR", "EZVPN_LOG_DIR"];

/// Reject a non-absolute directory override. An unset/empty value is accepted
/// (the platform default is used instead).
///
/// The daemon `chdir("/")`s and every subcommand must resolve the same fixed
/// location, so a relative override would silently point different invocations
/// at different directories — fail fast instead.
fn check_absolute_dir(var: &str, val: Option<&OsStr>) -> VpnResult<()> {
    if let Some(val) = val.filter(|v| !v.is_empty())
        && !Path::new(val).is_absolute()
    {
        return Err(VpnError::config(format!(
            "{var} must be an absolute path, got {:?}",
            Path::new(val).display()
        )));
    }
    Ok(())
}

/// Validate the directory-override environment variables at startup, before any
/// Tokio runtime or daemonization. Each, if set, must be an absolute path.
pub(crate) fn validate_dir_env() -> VpnResult<()> {
    for var in DIR_ENV_VARS {
        check_absolute_dir(var, std::env::var_os(var).as_deref())?;
    }
    Ok(())
}

/// Create `dir` owner-only (`0700` on Unix) if it does not already exist,
/// returning the path. Backs [`ensure_runtime_dir`] and [`ensure_log_dir`].
fn ensure_dir(dir: PathBuf) -> std::io::Result<PathBuf> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        // Create owner-only (0700) atomically so there is no window where the
        // directory is world/group-accessible. `recursive(true)` makes this a
        // no-op (permissions left untouched) when an admin pre-created it.
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&dir)?;
    }
    #[cfg(not(unix))]
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}

/// Ensure the runtime directory exists, creating it owner-only (`0700` on Unix)
/// on first creation. Returns the directory path. Called from write paths (lock
/// acquisition); read-only queries (`status`/`list`) do not create it.
pub(crate) fn ensure_runtime_dir() -> std::io::Result<PathBuf> {
    ensure_dir(runtime_dir())
}

/// Ensure the log directory exists, creating it owner-only (`0700` on Unix) on
/// first creation. Returns the directory path. Called when setting up the
/// daemon log.
///
/// Only the Unix daemonization path creates the log dir up front, so this is
/// Unix-only; elsewhere `log_dir` is resolved without pre-creating it.
#[cfg(unix)]
pub(crate) fn ensure_log_dir() -> std::io::Result<PathBuf> {
    ensure_dir(log_dir())
}

/// Which single-instance role a lock guards.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockRole {
    /// VPN client instance.
    Client,
    /// VPN server instance.
    Server,
}

impl LockRole {
    /// Short slug used to build runtime file names for this role.
    pub(crate) fn slug(self) -> &'static str {
        match self {
            LockRole::Client => "client",
            LockRole::Server => "server",
        }
    }

    /// Human-readable name used in error messages.
    fn description(self) -> &'static str {
        match self {
            LockRole::Client => "VPN client",
            LockRole::Server => "VPN server",
        }
    }
}

/// Maximum length of an instance name.
const MAX_INSTANCE_NAME_LEN: usize = 64;

/// Build the base runtime file name for a role + instance, e.g.
/// `ezvpn-client-default`. Both the instance lock and the status control
/// socket derive their paths from this so they stay consistent for a given
/// (role, instance) within a single user.
pub(crate) fn runtime_base_name(role: LockRole, instance: &str) -> String {
    format!("ezvpn-{}-{}", role.slug(), instance)
}

/// Validate an instance name before it is used as part of a runtime file name.
///
/// Names must be non-empty, at most [`MAX_INSTANCE_NAME_LEN`] characters, and
/// contain only ASCII letters, digits, and underscores. This keeps the name
/// safe to embed in a path under [`runtime_dir`] (no traversal, no separators,
/// no surprising filename characters).
pub fn validate_instance_name(name: &str) -> VpnResult<()> {
    if name.is_empty() {
        return Err(VpnError::config("Instance name must not be empty"));
    }
    if name.len() > MAX_INSTANCE_NAME_LEN {
        return Err(VpnError::config(format!(
            "Instance name must be at most {MAX_INSTANCE_NAME_LEN} characters"
        )));
    }
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
    {
        return Err(VpnError::config(
            "Instance name may only contain ASCII letters, digits, and underscores",
        ));
    }
    Ok(())
}

/// Extract the instance name from a lock file name for `role`, if it matches.
///
/// Inverse of [`runtime_base_name`] for the `.lock` suffix:
/// `ezvpn-client-work.lock` -> `Some("work")`. Returns `None` for names that
/// don't match the role's prefix/suffix or whose instance part is empty.
fn instance_from_lock_name(file_name: &str, role: LockRole) -> Option<&str> {
    file_name
        .strip_prefix(&format!("ezvpn-{}-", role.slug()))?
        .strip_suffix(".lock")
        .filter(|instance| !instance.is_empty())
}

/// List instance names that currently have a lock file for `role` in the
/// runtime directory.
///
/// Lock files are intentionally not removed on exit (see [`VpnLock`]'s `Drop`),
/// so this includes **stale** entries from instances that have since exited.
/// Callers that want only *running* instances should probe each one (e.g. via
/// the control socket). Names that don't pass [`validate_instance_name`] are
/// skipped, and an unreadable runtime directory yields an empty list. The
/// result is sorted for stable output.
pub(crate) fn list_locked_instances(role: LockRole) -> Vec<String> {
    let Ok(entries) = std::fs::read_dir(runtime_dir()) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|entry| {
            let file_name = entry.file_name();
            let instance = instance_from_lock_name(file_name.to_str()?, role)?;
            validate_instance_name(instance).ok()?;
            Some(instance.to_string())
        })
        .collect();
    names.sort();
    names
}

/// A file-based lock to ensure a single VPN client or server instance.
pub struct VpnLock {
    /// Path to the lock file.
    path: PathBuf,
    /// The lock file handle (kept open to maintain lock).
    file: File,
}

impl VpnLock {
    /// Acquire the single-instance lock for the given role.
    ///
    /// Returns an error if another instance of the same role and instance name
    /// is already running.
    pub fn acquire(role: LockRole, instance: &str) -> VpnResult<Self> {
        // Guard against unchecked input (separators/traversal) reaching the lock
        // path; non-CLI callers may bypass the earlier CLI validation.
        validate_instance_name(instance)?;
        let path = Self::lock_path(role, instance);

        // Ensure the runtime directory (the lock file's parent) exists.
        ensure_runtime_dir().map_err(|e| {
            VpnError::config_with_source("Failed to create runtime directory", e)
        })?;

        // Open or create the lock file (do not truncate before acquiring lock)
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| VpnError::config_with_source("Failed to open lock file", e))?;

        // Try to acquire exclusive lock (non-blocking) via std's native file
        // locking (stabilized in Rust 1.89).
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => {
                return Err(VpnError::config(format!(
                    "Another {} is already running. Only one instance allowed.",
                    role.description()
                )));
            }
            Err(TryLockError::Error(e)) => {
                return Err(VpnError::config_with_source(
                    "Failed to acquire VPN lock",
                    e,
                ));
            }
        }

        // Now that we hold the lock, truncate and write our PID
        file.set_len(0)
            .map_err(|e| VpnError::config_with_source("Failed to truncate lock file", e))?;
        file.seek(SeekFrom::Start(0))
            .map_err(|e| VpnError::config_with_source("Failed to seek lock file", e))?;
        writeln!(file, "{}", std::process::id())
            .map_err(|e| VpnError::config_with_source("Failed to write PID to lock file", e))?;

        log::debug!("Acquired VPN lock: {}", path.display());

        Ok(Self { path, file })
    }

    /// Get the path to the lock file for the given role and instance.
    fn lock_path(role: LockRole, instance: &str) -> PathBuf {
        runtime_dir().join(format!("{}.lock", runtime_base_name(role, instance)))
    }
}

/// Read the PID recorded in an instance's lock file.
///
/// Returns `Ok(None)` if no lock file exists (instance never started) or its
/// contents aren't a valid PID. Used by `client stop` to signal the process.
///
/// `client stop` signals via `SIGTERM`, which only exists on Unix, so this
/// PID-reading helper is Unix-only.
#[cfg(unix)]
pub(crate) fn read_instance_pid(role: LockRole, instance: &str) -> std::io::Result<Option<u32>> {
    // Re-validate (like `acquire`) so a separator/traversal name cannot reach
    // `lock_path` through this pub(crate) helper, even if a caller skips the
    // earlier CLI validation.
    validate_instance_name(instance)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;
    match std::fs::read_to_string(VpnLock::lock_path(role, instance)) {
        Ok(contents) => Ok(contents.trim().parse::<u32>().ok()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

impl Drop for VpnLock {
    fn drop(&mut self) {
        if let Err(e) = self.file.unlock() {
            log::warn!(
                "Failed to unlock VPN lock file {}: {}",
                self.path.display(),
                e
            );
        }

        // The lock is automatically released when the file is closed,
        // which happens when self.file is dropped. We don't remove the lock file
        // to avoid a race condition where another process could acquire a lock
        // on the about-to-be-unlinked inode while a third process creates a new
        // file with the same name.
        log::debug!("Released VPN lock: {}", self.path.display());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A single test covers both roles. Rust runs tests in parallel by default,
    // so keeping all acquisition of these process-wide file locks in one test
    // function avoids cross-test races.
    #[test]
    fn test_lock_acquire_release() {
        // Client and server use separate lock files, so both can be held at
        // the same time.
        assert_ne!(
            VpnLock::lock_path(LockRole::Client, "default"),
            VpnLock::lock_path(LockRole::Server, "default")
        );
        let client =
            VpnLock::acquire(LockRole::Client, "default").expect("Should acquire client lock");
        let server =
            VpnLock::acquire(LockRole::Server, "default").expect("Should acquire server lock");

        // A second lock attempt for the same role+instance fails while one is held.
        assert!(VpnLock::acquire(LockRole::Client, "default").is_err());
        assert!(VpnLock::acquire(LockRole::Server, "default").is_err());

        // Drop releases the locks.
        drop(client);
        drop(server);

        // Should be able to acquire again after release.
        let _client2 =
            VpnLock::acquire(LockRole::Client, "default").expect("Should acquire client again");
        let _server2 =
            VpnLock::acquire(LockRole::Server, "default").expect("Should acquire server again");
    }

    // Two different client instances use different lock files, so both can be
    // held at the same time. Kept in its own test function (distinct instance
    // names) so it does not race the process-wide locks above.
    #[test]
    fn test_distinct_instances_coexist() {
        assert_ne!(
            VpnLock::lock_path(LockRole::Client, "alpha"),
            VpnLock::lock_path(LockRole::Client, "beta")
        );
        let a = VpnLock::acquire(LockRole::Client, "alpha").expect("acquire alpha");
        let b = VpnLock::acquire(LockRole::Client, "beta").expect("acquire beta");

        // Re-acquiring the same instance fails while it is held.
        assert!(VpnLock::acquire(LockRole::Client, "alpha").is_err());

        drop(a);
        drop(b);
    }

    #[test]
    fn test_instance_from_lock_name() {
        assert_eq!(
            instance_from_lock_name("ezvpn-client-work.lock", LockRole::Client),
            Some("work")
        );
        assert_eq!(
            instance_from_lock_name("ezvpn-server-default.lock", LockRole::Server),
            Some("default")
        );
        // Wrong role prefix.
        assert_eq!(
            instance_from_lock_name("ezvpn-server-default.lock", LockRole::Client),
            None
        );
        // Not a lock file (e.g. the control socket) or empty instance.
        assert_eq!(
            instance_from_lock_name("ezvpn-client-work.sock", LockRole::Client),
            None
        );
        assert_eq!(
            instance_from_lock_name("ezvpn-client-.lock", LockRole::Client),
            None
        );
        assert_eq!(
            instance_from_lock_name("unrelated.lock", LockRole::Client),
            None
        );
    }

    #[test]
    fn test_validate_instance_name() {
        for ok in ["default", "work", "a_b_1", "A1", "x"] {
            assert!(validate_instance_name(ok).is_ok(), "{ok} should be valid");
        }
        for bad in ["", "../x", "a/b", "a-b", "a.b", "has space", "tab\t"] {
            assert!(
                validate_instance_name(bad).is_err(),
                "{bad:?} should be invalid"
            );
        }
        // Over-length name is rejected.
        let too_long = "a".repeat(MAX_INSTANCE_NAME_LEN + 1);
        assert!(validate_instance_name(&too_long).is_err());
        // Exactly at the limit is accepted.
        let at_limit = "a".repeat(MAX_INSTANCE_NAME_LEN);
        assert!(validate_instance_name(&at_limit).is_ok());
    }

    #[test]
    fn test_check_absolute_dir() {
        // Unset and empty are accepted (platform default is used).
        assert!(check_absolute_dir("EZVPN_RUNTIME_DIR", None).is_ok());
        assert!(check_absolute_dir("EZVPN_RUNTIME_DIR", Some(OsStr::new(""))).is_ok());

        // Absolute paths are accepted.
        #[cfg(unix)]
        assert!(check_absolute_dir("EZVPN_LOG_DIR", Some(OsStr::new("/var/log/ezvpn"))).is_ok());
        #[cfg(windows)]
        assert!(
            check_absolute_dir("EZVPN_LOG_DIR", Some(OsStr::new(r"C:\ProgramData\ezvpn"))).is_ok()
        );

        // Relative paths are rejected.
        for rel in ["ezvpn", "./ezvpn", "../ezvpn", "a/b"] {
            assert!(
                check_absolute_dir("EZVPN_RUNTIME_DIR", Some(OsStr::new(rel))).is_err(),
                "{rel:?} should be rejected"
            );
        }
    }
}
