//! ezvpn
//!
//! IP-over-QUIC VPN tunnel via iroh P2P connections.
//! Uses ezvpn auth tokens for access control and TLS 1.3/QUIC for encryption.

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
compile_error!("the ezvpn CLI only supports Linux, macOS, and Windows");

// The desktop CLI consumes the `ezvpn` library crate (see src/lib.rs). Bring the
// modules it references by bare path into scope so the existing `auth::`,
// `runtime::`, `control::`, `secret::` call sites keep resolving unchanged.
use ezvpn::{auth, control, runtime, secret};

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ipnet::{Ipv4Net, Ipv6Net};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::num::NonZeroU32;
use std::path::{Path, PathBuf};

use ezvpn::config::file_config::{
    ResolvedVpnClientConfig, ResolvedVpnServerConfig, VpnClientConfig as TomlClientConfig,
    VpnClientConfigBuilder, VpnServerConfig as TomlServerConfig, expand_tilde,
    load_vpn_client_config, load_vpn_server_config,
};
use ezvpn::runtime::LockRole;
use ezvpn::transport::endpoint::{
    RELAY_CONNECT_TIMEOUT, create_client_endpoint, create_server_endpoint, load_secret,
};
// Runtime config types (different from the TOML config types in config::file_config)
use ezvpn::config::{VpnClientConfig, VpnServerConfig};
use ezvpn::tunnel::{VpnClient, VpnServer};

#[derive(Parser)]
#[command(name = "ezvpn")]
#[command(version)]
#[command(about = "IP-over-QUIC VPN tunnel via iroh P2P")]
struct Args {
    #[command(subcommand)]
    command: Command,
}

// This enum is parsed once at startup; the size disparity between variants is
// irrelevant here, and boxing fields would fight the clap derive macro.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Command {
    /// VPN server commands (start, status, list).
    Server {
        #[command(subcommand)]
        action: ServerAction,
    },
    /// VPN client commands (start, stop, status, list).
    Client {
        #[command(subcommand)]
        action: ClientAction,
    },
    /// Generate a new private key for persistent server identity
    ///
    /// Creates a secret key file for the server config's [iroh] secret_file.
    /// The server's EndpointId remains constant when using the same key.
    #[command(arg_required_else_help = true)]
    GenerateServerKey {
        /// Path where to save the private key file
        #[arg(short, long)]
        output: PathBuf,

        /// Overwrite existing file if it exists
        #[arg(long)]
        force: bool,

        /// Output the result as JSON
        #[arg(long)]
        json: bool,
    },
    /// Show the server's public EndpointId derived from a private key
    ///
    /// Clients use this EndpointId with --server-node-id to connect.
    #[command(arg_required_else_help = true)]
    ShowServerId {
        /// Path to the private key file
        #[arg(short, long)]
        secret_file: PathBuf,

        /// Output the result as JSON
        #[arg(long)]
        json: bool,
    },
    /// Generate a client authentication token
    ///
    /// Tokens are shared with clients for authentication (like API keys).
    /// Server configures accepted tokens via [auth] auth_tokens or auth_tokens_file.
    GenerateAuthToken {
        /// Number of tokens to generate (default: 1)
        #[arg(short, long, default_value = "1")]
        count: usize,

        /// Output the tokens as a JSON array
        #[arg(long)]
        json: bool,
    },
}

/// Server subcommands.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum ServerAction {
    /// Start the VPN server (accepts connections and assigns IPs).
    ///
    /// Requires a config file. Use -c to specify a path or --default-config for
    /// vpn_server.toml in the system config dir (/etc/ezvpn on Linux,
    /// /usr/local/etc/ezvpn on macOS, %ProgramData%\ezvpn on Windows). See
    /// vpn_server.toml.example for format.
    #[command(arg_required_else_help = true)]
    Start {
        /// Config file path (required unless --default-config is used)
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,

        /// Use vpn_server.toml in the system config dir (/etc/ezvpn,
        /// /usr/local/etc/ezvpn on macOS, %ProgramData%\ezvpn on Windows)
        #[arg(long)]
        default_config: bool,
    },
    /// Query the status of the running VPN server on this host.
    Status {
        /// Output the raw status snapshot as JSON
        #[arg(long)]
        json: bool,
    },
    /// List VPN server instances on this host.
    List {
        /// Output the raw instance list as JSON
        #[arg(long)]
        json: bool,
    },
}

/// Client subcommands.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum ClientAction {
    /// Start the VPN client (connects to server and establishes tunnel).
    #[command(arg_required_else_help = true)]
    Start {
        /// Config file path
        #[arg(short = 'c', long)]
        config: Option<PathBuf>,

        /// Use vpn_client.toml in the system config dir (/etc/ezvpn,
        /// /usr/local/etc/ezvpn on macOS, %ProgramData%\ezvpn on Windows)
        #[arg(long)]
        default_config: bool,

        /// EndpointId of the VPN server to connect to
        #[arg(short = 'n', long)]
        server_node_id: Option<String>,

        /// Custom relay server URL(s)
        #[arg(long = "relay-url")]
        relay_urls: Vec<String>,

        /// Authentication token to send to server
        #[arg(long)]
        auth_token: Option<String>,

        /// Path to file containing authentication token
        #[arg(long)]
        auth_token_file: Option<PathBuf>,

        /// Additional IPv4 route CIDRs through the VPN (optional, repeatable).
        /// The server's VPN address is always routed by default.
        /// Full tunnel: --route 0.0.0.0/0
        /// Split tunnel: --route 192.168.1.0/24 --route 10.0.0.0/8
        #[arg(long = "route")]
        routes: Vec<String>,

        /// IPv6 route CIDRs through the VPN (optional, repeatable)
        /// Full tunnel: --route6 ::/0
        /// Split tunnel: --route6 fd00::/64
        #[arg(long = "route6")]
        routes6: Vec<String>,

        /// Enable auto-reconnect (override config's auto_reconnect = false)
        #[arg(long, conflicts_with = "no_auto_reconnect")]
        auto_reconnect: bool,

        /// Disable auto-reconnect (exit on first disconnection)
        #[arg(long, conflicts_with = "auto_reconnect")]
        no_auto_reconnect: bool,

        /// Maximum reconnect attempts (unlimited if not specified)
        #[arg(long, conflicts_with = "no_auto_reconnect")]
        max_reconnect_attempts: Option<NonZeroU32>,

        /// Instance name. Scopes the lock and status socket so multiple clients
        /// can run at once. Allowed: ASCII letters, digits, underscores.
        #[arg(long, default_value = "default")]
        instance: String,

        /// Run in the background as a daemon (Unix only). Logs are written to
        /// <log_dir>/ezvpn-client-<instance>.log, size-capped at 10 MiB
        /// (EZVPN_LOG_MAX_BYTES) with one rotated <name>.log.1 backup.
        #[arg(long)]
        daemon: bool,
    },
    /// Stop a running VPN client on Unix (sends SIGTERM for a graceful shutdown).
    Stop {
        /// Instance name of the client to stop (see `client start --instance`).
        #[arg(long, default_value = "default")]
        instance: String,

        /// Output the result as JSON
        #[arg(long)]
        json: bool,
    },
    /// Query the status of the running VPN client on this host.
    Status {
        /// Output the raw status snapshot as JSON
        #[arg(long)]
        json: bool,

        /// Instance name of the client to query (see `client start --instance`).
        #[arg(long, default_value = "default")]
        instance: String,
    },
    /// List VPN client instances on this host.
    List {
        /// Output the raw instance list as JSON
        #[arg(long)]
        json: bool,
    },
}

/// Resolve VPN server config from CLI and/or config file.
fn resolve_server_config(
    config: Option<PathBuf>,
    default_config: bool,
) -> Result<(Option<TomlServerConfig>, bool)> {
    if let Some(path) = config {
        let cfg = load_vpn_server_config(Some(path.as_path()))?;
        Ok((Some(cfg), true))
    } else if default_config {
        let cfg = load_vpn_server_config(None)?;
        Ok((Some(cfg), true))
    } else {
        Ok((None, false))
    }
}

/// Resolve VPN client config from CLI and/or config file.
fn resolve_client_config(
    config: Option<PathBuf>,
    default_config: bool,
) -> Result<(Option<TomlClientConfig>, bool)> {
    if let Some(path) = config {
        let cfg = load_vpn_client_config(Some(path.as_path()))?;
        Ok((Some(cfg), true))
    } else if default_config {
        let cfg = load_vpn_client_config(None)?;
        Ok((Some(cfg), true))
    } else {
        Ok((None, false))
    }
}

/// Log the binary name and version at tunnel startup (server/client only).
fn log_version() {
    log::info!("{} v{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
}

/// Install the global logger. Must be called exactly once per process; for the
/// client daemon this happens *after* the fork so output lands in the log file.
fn init_logger() {
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info,iroh=warn,tracing=warn"),
    )
    .init();
}

/// Build the multi-threaded Tokio runtime used by the async commands. Built
/// after any daemonization fork — a runtime cannot survive `fork()`.
fn build_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(Into::into)
}

/// Default daemon log-file path for a client instance (absolute; in the log
/// dir, so it survives the daemon's `chdir("/")`).
fn client_log_path(instance: &str) -> PathBuf {
    runtime::log_dir().join(format!(
        "{}.log",
        runtime::runtime_base_name(LockRole::Client, instance)
    ))
}

fn main() -> Result<()> {
    let args = Args::parse();

    // Validate directory-override env vars up front, before building any Tokio
    // runtime or daemonizing: a relative EZVPN_RUNTIME_DIR / EZVPN_LOG_DIR would
    // resolve differently across subcommands and after the daemon's chdir("/").
    runtime::validate_dir_env()?;

    match args.command {
        // `client start` is the only command that may daemonize. Its whole
        // validation phase runs synchronously here so config/flag/path errors
        // surface in the foreground, and the fork (when `--daemon`) happens
        // BEFORE the Tokio runtime is built — a runtime cannot survive fork().
        Command::Client {
            action:
                ClientAction::Start {
                    config,
                    default_config,
                    server_node_id,
                    relay_urls,
                    auth_token,
                    auth_token_file,
                    routes,
                    routes6,
                    auto_reconnect,
                    no_auto_reconnect,
                    max_reconnect_attempts,
                    instance,
                    daemon,
                },
        } => {
            runtime::validate_instance_name(&instance)?;
            let mut resolved = prepare_client_start(
                config,
                default_config,
                server_node_id,
                relay_urls,
                auth_token,
                auth_token_file,
                routes,
                routes6,
                auto_reconnect,
                no_auto_reconnect,
                max_reconnect_attempts,
            )?;

            let daemon_log = if daemon {
                // The daemon does chdir("/"), which breaks cwd-relative paths.
                // Resolve the files the client reads post-fork to absolute now;
                // this also surfaces missing-file errors in the foreground.
                canonicalize_client_paths(&mut resolved)?;
                let log_path = client_log_path(&instance);
                eprintln!("ezvpn: daemonizing; logs at {}", log_path.display());
                daemonize_client(&log_path)?;
                Some(log_path.display().to_string())
            } else {
                None
            };

            init_logger();
            log_version();
            build_runtime()?.block_on(run_vpn_client(resolved, &instance, daemon_log))
        }

        // Synchronous commands: no Tokio runtime is ever created.
        Command::GenerateServerKey {
            output,
            force,
            json,
        } => {
            init_logger();
            secret::generate_secret(expand_tilde(&output), force, json)
        }
        Command::ShowServerId { secret_file, json } => {
            init_logger();
            secret::show_id(expand_tilde(&secret_file), json)
        }
        Command::GenerateAuthToken { count, json } => {
            init_logger();
            let tokens: Vec<String> = (0..count).map(|_| auth::generate_token()).collect();
            if json {
                println!("{}", serde_json::to_string_pretty(&tokens)?);
            } else {
                for token in &tokens {
                    println!("{token}");
                }
            }
            Ok(())
        }
        // Everything else is async but never daemonizes: run on a fresh runtime.
        command => {
            init_logger();
            build_runtime()?.block_on(run_async(command))
        }
    }
}

/// Dispatch the async commands that do not daemonize, on the current runtime.
async fn run_async(command: Command) -> Result<()> {
    match command {
        Command::Server {
            action:
                ServerAction::Start {
                    config,
                    default_config,
                },
        } => {
            log_version();
            // Config file is required for VPN server
            if config.is_none() && !default_config {
                anyhow::bail!(
                    "VPN server requires a config file.\n\
                     Use -c <FILE> or --default-config (vpn_server.toml in the system \
                     config dir: /etc/ezvpn, /usr/local/etc/ezvpn on macOS, \
                     %ProgramData%\\ezvpn on Windows)\n\
                     See vpn_server.toml.example for format."
                );
            }

            // Load and validate config file
            let (cfg, _from_file) = resolve_server_config(config, default_config)?;
            let cfg = cfg
                .expect("resolve_server_config returns Some when config or default_config is set");
            cfg.validate()?;

            // Build resolved config from config file
            let resolved = ResolvedVpnServerConfig::from_config(&cfg)?;

            run_vpn_server(resolved).await
        }
        Command::Server {
            action: ServerAction::Status { json },
        } => show_status(LockRole::Server, json, "default").await,
        Command::Server {
            action: ServerAction::List { json },
        } => show_list(LockRole::Server, json).await,
        Command::Client {
            action: ClientAction::Stop { instance, json },
        } => stop_client(&instance, json).await,
        Command::Client {
            action: ClientAction::Status { json, instance },
        } => {
            runtime::validate_instance_name(&instance)?;
            show_status(LockRole::Client, json, &instance).await
        }
        Command::Client {
            action: ClientAction::List { json },
        } => show_list(LockRole::Client, json).await,
        // Handled synchronously in main().
        Command::Client {
            action: ClientAction::Start { .. },
        }
        | Command::GenerateServerKey { .. }
        | Command::ShowServerId { .. }
        | Command::GenerateAuthToken { .. } => {
            unreachable!("dispatched synchronously in main()")
        }
    }
}

/// Synchronous validation/build phase for `client start`. Runs before any
/// daemonization so config and flag errors surface in the foreground.
#[allow(clippy::too_many_arguments)]
fn prepare_client_start(
    config: Option<PathBuf>,
    default_config: bool,
    server_node_id: Option<String>,
    relay_urls: Vec<String>,
    auth_token: Option<String>,
    auth_token_file: Option<PathBuf>,
    routes: Vec<String>,
    routes6: Vec<String>,
    auto_reconnect: bool,
    no_auto_reconnect: bool,
    max_reconnect_attempts: Option<NonZeroU32>,
) -> Result<ResolvedVpnClientConfig> {
    // Load config file if specified
    let (cfg, from_file) = resolve_client_config(config, default_config)?;
    if from_file && let Some(ref c) = cfg {
        c.validate()?;
    }

    // Convert mutually exclusive flags to Option<bool>
    // --auto-reconnect => Some(true), --no-auto-reconnect => Some(false), neither => None
    assert!(
        !(auto_reconnect && no_auto_reconnect),
        "both --auto-reconnect and --no-auto-reconnect were set (clap conflicts_with should prevent this)"
    );
    let auto_reconnect_opt = match (auto_reconnect, no_auto_reconnect) {
        (true, false) => Some(true),    // --auto-reconnect: enable reconnect
        (false, true) => Some(false),   // --no-auto-reconnect: disable reconnect
        (false, false) => None,         // neither: use config/default
        (true, true) => unreachable!(), // guarded by assert above
    };

    // Fail fast if we lack the privileges to create a TUN device, before opening
    // any network connection or (with --daemon) forking into the background. The
    // client otherwise only discovers this after connecting to the server and
    // completing the handshake.
    ezvpn::net::device::ensure_tun_permission()?;

    // Build resolved config: defaults -> config file -> CLI
    VpnClientConfigBuilder::new()
        .apply_defaults()
        .apply_config(cfg.as_ref())
        .apply_cli(
            server_node_id,
            auth_token,
            auth_token_file.map(|p| expand_tilde(&p)),
            routes,
            routes6,
            relay_urls,
            auto_reconnect_opt,
            max_reconnect_attempts,
        )
        .build()
}

/// Resolve the cwd-relative files the client reads after daemonizing to
/// absolute paths (the daemon does `chdir("/")`). Errors are reported in the
/// foreground before the fork.
fn canonicalize_client_paths(resolved: &mut ResolvedVpnClientConfig) -> Result<()> {
    for (field, slot) in [("auth token file", &mut resolved.auth_token_file)] {
        if let Some(path) = slot.as_ref() {
            let abs = std::fs::canonicalize(path)
                .with_context(|| format!("resolving {field} {}", path.display()))?;
            *slot = Some(abs);
        }
    }
    Ok(())
}

/// Default maximum size (bytes) of the active daemon log before it is rotated.
/// On reaching the cap the current log is renamed to `<name>.1` (replacing any
/// previous backup) and a fresh log is started, so disk use stays bounded at
/// roughly `2 *` the cap. Override with `EZVPN_LOG_MAX_BYTES`.
#[cfg(unix)]
const DAEMON_LOG_MAX_BYTES: u64 = 10 * 1024 * 1024;

/// Resolve the daemon log size cap, honoring the `EZVPN_LOG_MAX_BYTES`
/// environment variable (bytes) and falling back to [`DAEMON_LOG_MAX_BYTES`].
/// Called before the logger is installed and the fork, so warnings reach the
/// foreground stderr.
#[cfg(unix)]
fn daemon_log_max_bytes() -> u64 {
    parse_log_max_bytes(std::env::var_os("EZVPN_LOG_MAX_BYTES").as_deref())
}

/// Parse a raw `EZVPN_LOG_MAX_BYTES` value into a byte cap. `None`, empty, and
/// invalid/zero values fall back to [`DAEMON_LOG_MAX_BYTES`]; invalid (non-empty)
/// values also warn to stderr.
#[cfg(unix)]
fn parse_log_max_bytes(raw: Option<&std::ffi::OsStr>) -> u64 {
    let Some(raw) = raw.filter(|r| !r.is_empty()) else {
        return DAEMON_LOG_MAX_BYTES;
    };
    match raw.to_str().and_then(|s| s.trim().parse::<u64>().ok()) {
        Some(n) if n > 0 => n,
        _ => {
            eprintln!(
                "ezvpn: ignoring invalid EZVPN_LOG_MAX_BYTES={}; using default {} bytes",
                raw.to_string_lossy(),
                DAEMON_LOG_MAX_BYTES
            );
            DAEMON_LOG_MAX_BYTES
        }
    }
}

/// Fork the current process into the background as a daemon (Unix only). Must
/// be called before the Tokio runtime is built. Sets `chdir("/")` and routes
/// stdout/stderr through a pipe drained by a background thread that writes to a
/// size-capped, rotating log at `log_path` (see [`DAEMON_LOG_MAX_BYTES`]). The
/// parent process exits inside `start()`.
///
/// The pipe is needed because daemonization `dup2`s the daemon's stdout/stderr
/// directly onto the log file; writing that way is unbounded. Draining the fds
/// in-process lets us enforce the cap while still capturing everything the
/// daemon emits (log lines, panics, library stdout/stderr).
#[cfg(unix)]
fn daemonize_client(log_path: &Path) -> Result<()> {
    use std::os::fd::{FromRawFd, OwnedFd};

    // The log lives in the log dir, which may not exist on first run.
    runtime::ensure_log_dir().context("creating log directory for daemon log")?;

    // Resolve the cap before the fork so any warning lands on the foreground
    // terminal rather than (post-redirect) in the log file itself.
    let max_bytes = daemon_log_max_bytes();

    // Self-pipe: the daemon's stdout/stderr become the write end; a background
    // thread (spawned post-fork) reads the read end and writes the capped log.
    let mut fds = [0 as libc::c_int; 2];
    // SAFETY: `fds` is a valid 2-element array for `pipe` to populate.
    if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error()).context("creating daemon log pipe");
    }
    // SAFETY: `pipe` succeeded, so both fds are open and now owned by us.
    let read_end = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write_end = unsafe { OwnedFd::from_raw_fd(fds[1]) };

    // stdout and stderr each need their own handle onto the write end; both are
    // moved into daemonize, which `dup2`s them onto fd 1/2 and drops these
    // copies. The only surviving write ends are then fd 1/2 in the daemon, so
    // the reader sees EOF exactly when the daemon exits.
    let stdout = std::fs::File::from(
        write_end
            .try_clone()
            .context("cloning daemon log pipe write end")?,
    );
    let stderr = std::fs::File::from(write_end);

    daemonix::Daemonize::new()
        .working_directory("/")
        .stdout(stdout)
        .stderr(stderr)
        .start()
        .context("failed to daemonize")?;

    // Post-fork, single-threaded daemon: drain the pipe into the capped log on
    // a dedicated thread. It is detached and lives for the daemon's lifetime,
    // exiting on EOF when the daemon closes stdout/stderr at shutdown.
    let read_file = std::fs::File::from(read_end);
    let path = log_path.to_path_buf();
    std::thread::Builder::new()
        .name("ezvpn-logwriter".into())
        .spawn(move || drain_to_capped_log(read_file, &path, max_bytes))
        .context("spawning daemon log writer thread")?;

    Ok(())
}

/// Path of the single rotation backup: the active log name with `.1` appended
/// (e.g. `ezvpn-client-default.log` -> `ezvpn-client-default.log.1`).
#[cfg(unix)]
fn rotated_log_path(path: &Path) -> PathBuf {
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".1");
    path.with_file_name(name)
}

/// Drain `pipe` (the daemon's redirected stdout/stderr) into a size-capped log
/// at `path`, rotating to `<path>.1` when the active file would exceed
/// `max_bytes`. Runs on a dedicated thread for the daemon's lifetime and
/// returns when the pipe reaches EOF (daemon shutdown).
#[cfg(unix)]
fn drain_to_capped_log(mut pipe: std::fs::File, path: &Path, max_bytes: u64) {
    use std::io::{Read, Write};

    let open_active = || {
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
    };
    // `None` means the log could not be opened. We still drain the pipe (so the
    // daemon never blocks on a full pipe) and retry opening on later chunks,
    // rather than exiting the thread or writing to a stale rotated handle.
    let (mut file, mut size) = match open_active() {
        Ok(f) => {
            let len = f.metadata().map(|m| m.len()).unwrap_or(0);
            (Some(f), len)
        }
        Err(_) => (None, 0),
    };

    // Chunks are at most `buf.len()`, so a rotated file never exceeds
    // `max_bytes + buf.len()`.
    let mut buf = [0u8; 16 * 1024];
    loop {
        let n = match pipe.read(&mut buf) {
            Ok(0) => return, // EOF: the daemon is exiting.
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return,
        };

        // Recover from an earlier failed open before writing this chunk.
        if file.is_none()
            && let Ok(f) = open_active()
        {
            size = f.metadata().map(|m| m.len()).unwrap_or(0);
            file = Some(f);
        }

        // Rotate before writing if this chunk would breach the cap. On a failed
        // reopen, fall back to discarding (still draining) and retry next chunk;
        // never keep writing to the rotated handle.
        if size > 0
            && size + n as u64 > max_bytes
            && std::fs::rename(path, rotated_log_path(path)).is_ok()
        {
            file = open_active().ok();
            size = 0;
        }

        // Write if we have a file, else discard. Either way the pipe is drained
        // (and write errors are ignored) so the daemon's logging never blocks.
        if let Some(f) = file.as_mut()
            && f.write_all(&buf[..n]).is_ok()
        {
            size += n as u64;
        }
    }
}

#[cfg(not(unix))]
fn daemonize_client(_log_path: &Path) -> Result<()> {
    anyhow::bail!("--daemon is only supported on Unix");
}

/// Wait for a shutdown signal (SIGTERM/SIGINT on Unix, Ctrl-C elsewhere).
#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("install SIGINT handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

/// One-shot result document for `client stop --json`. `pid` is omitted when
/// the instance was not running.
#[cfg(unix)]
#[derive(serde::Serialize)]
struct StopReport<'a> {
    instance: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<u32>,
    /// `"not_running"` | `"stopped"` | `"signal_sent"` (signaled, but still
    /// shutting down when the wait timed out).
    result: &'static str,
}

/// Stop a running VPN client by signaling its process with SIGTERM. The client
/// catches the signal and shuts down gracefully (releasing its lock, removing
/// the status socket, and tearing down the TUN device). With `json`, prints a
/// single [`StopReport`] instead of the human progress lines.
#[cfg(unix)]
async fn stop_client(instance: &str, json: bool) -> Result<()> {
    runtime::validate_instance_name(instance)?;

    let report = |pid: Option<u32>, result: &'static str| -> Result<()> {
        let text = serde_json::to_string_pretty(&StopReport {
            instance,
            pid,
            result,
        })?;
        println!("{text}");
        Ok(())
    };

    // Confirm an instance is actually serving before signaling a PID.
    if control::query_status(LockRole::Client, instance).await?.is_none() {
        if json {
            return report(None, "not_running");
        }
        println!("ezvpn client (instance {instance}) is not running.");
        return Ok(());
    }

    let pid = runtime::read_instance_pid(LockRole::Client, instance)?
        .context("could not determine client PID from lock file")?;

    // SAFETY: a plain SIGTERM to a PID we just confirmed is a live instance.
    let rc = unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to signal client pid {pid}"));
    }
    if !json {
        println!("Sent stop signal to client (instance {instance}, pid {pid}).");
    }

    // Best-effort: wait briefly for the process to exit.
    for _ in 0..50 {
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        if control::query_status(LockRole::Client, instance).await?.is_none() {
            if json {
                return report(Some(pid), "stopped");
            }
            println!("Client stopped.");
            return Ok(());
        }
    }
    if json {
        return report(Some(pid), "signal_sent");
    }
    println!("Stop signal sent; client did not exit within 5s (still shutting down?).");
    Ok(())
}

#[cfg(not(unix))]
async fn stop_client(_instance: &str, _json: bool) -> Result<()> {
    anyhow::bail!("client stop is only supported on Unix");
}

/// Query and print the status of a running server/client via its control socket.
async fn show_status(role: LockRole, json: bool, instance: &str) -> Result<()> {
    let label = match role {
        LockRole::Server => "server",
        LockRole::Client => "client",
    };
    match control::query_status(role, instance).await? {
        Some(snapshot) => {
            control::print_status(&snapshot, json)?;
            Ok(())
        }
        None => {
            if json {
                println!("{{\"state\":\"not_running\"}}");
            } else {
                println!("ezvpn {label} is not running.");
            }
            Ok(())
        }
    }
}

/// List instances discovered on this host (one line each, or JSON).
async fn show_list(role: LockRole, json: bool) -> Result<()> {
    let instances = control::list_instances(role).await?;
    control::print_instances(role, &instances, json)?;
    Ok(())
}

/// Run VPN server.
async fn run_vpn_server(resolved: ResolvedVpnServerConfig) -> Result<()> {
    // Parse IPv4 network CIDR (optional, for IPv6-only servers)
    let network: Option<Ipv4Net> = resolved
        .network
        .as_ref()
        .map(|n| n.parse())
        .transpose()
        .context("Invalid VPN network CIDR")?;

    // Parse server IP if provided
    let server_ip: Option<Ipv4Addr> = resolved
        .server_ip
        .as_ref()
        .map(|ip_str| ip_str.parse())
        .transpose()
        .context("Invalid server IP address")?;

    // Parse IPv6 network CIDR (optional, for dual-stack)
    let network6: Option<Ipv6Net> = resolved
        .network6
        .as_ref()
        .map(|n| n.parse())
        .transpose()
        .context("Invalid IPv6 VPN network CIDR")?;

    // Parse server IPv6 if provided
    let server_ip6: Option<Ipv6Addr> = resolved
        .server_ip6
        .as_ref()
        .map(|ip_str| ip_str.parse())
        .transpose()
        .context("Invalid server IPv6 address")?;

    // Load and validate auth tokens (required for VPN server)
    let valid_tokens =
        auth::load_auth_tokens(&resolved.auth_tokens, resolved.auth_tokens_file.as_deref())
            .context("Failed to load authentication tokens")?;

    if valid_tokens.is_empty() {
        anyhow::bail!(
            "VPN server requires at least one authentication token.\n\
             Generate one with: ezvpn generate-auth-token\n\
             Then add to config file: auth_tokens = [\"<TOKEN>\"]"
        );
    }

    log::info!("Loaded {} authentication token(s)", valid_tokens.len());

    // Load secret key for persistent iroh identity (required for server)
    let secret_key = if let Some(ref path) = resolved.secret_file {
        load_secret(path).context("Failed to load secret key")?
    } else {
        anyhow::bail!(
            "VPN server requires a secret key file for persistent identity.\n\
             Generate one with: ezvpn generate-server-key -o <FILE>\n\
             Then add to config file: secret_file = \"<FILE>\""
        );
    };

    // Create VPN server config
    let config = VpnServerConfig {
        network,
        network6,
        server_ip,
        server_ip6,
        ip6_strategy: resolved.ip6_strategy,
        max_clients: 254,
        auth_tokens: Some(valid_tokens),
    };

    // Fail fast if we lack the privileges to create the TUN device, before
    // opening the iroh endpoint. The server otherwise only discovers this in
    // setup_tun() after the endpoint is up.
    ezvpn::net::device::ensure_tun_permission()?;

    // Create iroh endpoint(s) for signaling.
    // relay_only is hardcoded to false: VPN traffic is high-bandwidth and latency-sensitive,
    // making relay-only impractical. Direct P2P is strongly preferred; relay is only used
    // as automatic fallback when direct connection fails.
    // iroh selects one home relay per endpoint. A custom-relay server therefore
    // needs an endpoint on each relay so the same server identity is reachable
    // regardless of which configured relay a client can access.
    let endpoints = if resolved.relay_urls.is_empty() {
        vec![create_server_endpoint(
            &[],
            false, // relay_only - direct P2P preferred for VPN performance
            Some(secret_key),
        )
        .await
        .context("Failed to create iroh endpoint")?]
    } else {
        let mut relay_urls = resolved.relay_urls.clone();
        relay_urls.sort();
        relay_urls.dedup();
        let attempts = futures::future::join_all(relay_urls.into_iter().map(|relay_url| {
            let secret_key = secret_key.clone();
            async move {
                let endpoint = match tokio::time::timeout(
                    RELAY_CONNECT_TIMEOUT,
                    create_server_endpoint(
                        std::slice::from_ref(&relay_url),
                        false,
                        Some(secret_key),
                    ),
                )
                .await
                {
                    Ok(result) => result,
                    Err(_) => Err(anyhow::anyhow!(
                        "relay registration timed out after {}s",
                        RELAY_CONNECT_TIMEOUT.as_secs()
                    )),
                };
                (relay_url, endpoint)
            }
        }))
        .await;
        let mut endpoints = Vec::new();
        for (relay_url, result) in attempts {
            match result {
                Ok(endpoint) => {
                    log::info!("Server registered on custom relay {}", relay_url);
                    endpoints.push(endpoint);
                }
                Err(e) => log::warn!(
                    "Could not register server on custom relay {}: {:#}",
                    relay_url,
                    e
                ),
            }
        }
        if endpoints.is_empty() {
            anyhow::bail!("Failed to register the VPN server on any configured custom relay");
        }
        endpoints
    };

    let server_id = endpoints[0].id();
    log::info!("VPN Server Node ID: {}", server_id);
    log::info!(
        "Clients connect with: ezvpn client start --server-node-id {} --auth-token <TOKEN>",
        server_id
    );

    // Create and run VPN server
    let server = VpnServer::new(config, server_id)
        .await
        .context("Failed to create VPN server")?;

    server
        .run(endpoints)
        .await
        .map_err(|e| anyhow::anyhow!("VPN server error: {}", e))
}

/// Run VPN client.
async fn run_vpn_client(
    resolved: ResolvedVpnClientConfig,
    instance: &str,
    daemon_log: Option<String>,
) -> Result<()> {
    // Load auth token (from CLI or file)
    let token = if let Some(ref token) = resolved.auth_token {
        auth::validate_token(token).context("Invalid authentication token from CLI")?;
        token.clone()
    } else if let Some(ref path) = resolved.auth_token_file {
        auth::load_auth_token_from_file(path)
            .context("Failed to load authentication token from file")?
    } else {
        anyhow::bail!(
            "VPN client requires an authentication token.\n\
             Use --auth-token <TOKEN> or --auth-token-file <FILE>"
        );
    };

    // Parse IPv4 routes (optional - the server's VPN address is always routed by default)
    let parsed_routes: Vec<Ipv4Net> = resolved
        .routes
        .iter()
        .map(|r| r.parse::<Ipv4Net>())
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid route CIDR (e.g., 192.168.1.0/24)")?;

    // Parse IPv6 routes (optional)
    let parsed_routes6: Vec<Ipv6Net> = resolved
        .routes6
        .iter()
        .map(|r| r.parse::<Ipv6Net>())
        .collect::<Result<Vec<_>, _>>()
        .context("Invalid route6 CIDR (e.g., ::/0 or fd00::/64)")?;

    log::info!("Routing {} IPv4 CIDR(s) through VPN:", parsed_routes.len());
    for route in &parsed_routes {
        log::info!("  {}", route);
    }
    if !parsed_routes6.is_empty() {
        log::info!("Routing {} IPv6 CIDR(s) through VPN:", parsed_routes6.len());
        for route6 in &parsed_routes6 {
            log::info!("  {}", route6);
        }
    }

    // Create VPN client config
    let config = VpnClientConfig {
        server_node_id: resolved.server_node_id.clone(),
        auth_token: Some(token),
        routes: parsed_routes,
        routes6: parsed_routes6,
    };

    // Create iroh endpoint for signaling (ephemeral identity).
    // relay_only is hardcoded to false: VPN traffic is high-bandwidth and latency-sensitive,
    // making relay-only impractical. Direct P2P is strongly preferred; relay is only used
    // as automatic fallback when direct connection fails.
    let endpoint = create_client_endpoint(
        &resolved.relay_urls,
        false, // relay_only - direct P2P preferred for VPN performance
        None, // No persistent secret key - ephemeral
    )
    .await
    .context("Failed to create iroh endpoint")?;

    log::info!("VPN Client Node ID: {}", endpoint.id());

    // Create VPN client
    let client = VpnClient::new(config, instance)
        .map_err(|e| anyhow::anyhow!("Failed to create VPN client: {}", e))?;

    // Surface the daemon log-file path through the status socket (None when
    // running in the foreground).
    client.status_handle().set_log_file(daemon_log);

    // Spawn the status control-socket listener. It outlives individual
    // connections (e.g. across reconnects); the guard stops it when we return.
    let status_handle = client.status_handle();
    let _status_listener =
        control::spawn_status_listener(LockRole::Client, instance, move || {
            status_handle.snapshot()
        });
    match &_status_listener {
        Ok(_) => log::info!(
            "Status control socket ready (ezvpn client status --instance {instance})"
        ),
        Err(e) => log::warn!("Status control socket unavailable: {e}"),
    }
    let _status_listener = _status_listener.ok();

    // Connect with or without auto-reconnect. Race against a shutdown signal so
    // SIGTERM (e.g. `ezvpn client stop`) or Ctrl-C returns cleanly, letting
    // the guards/Drop tear down the lock, status socket, and TUN device.
    let run = async {
        if resolved.auto_reconnect {
            client
                .run_with_reconnect(
                    &endpoint,
                    &resolved.relay_urls,
                    resolved.max_reconnect_attempts,
                )
                .await
                .map_err(|e| anyhow::anyhow!("VPN connection error: {}", e))
        } else {
            log::info!("Auto-reconnect disabled, single connection attempt");
            client
                .connect(&endpoint, &resolved.relay_urls)
                .await
                .map_err(|e| anyhow::anyhow!("VPN connection error: {}", e))
        }
    };

    tokio::select! {
        res = run => res,
        _ = shutdown_signal() => {
            log::info!("Received shutdown signal, stopping VPN client");
            Ok(())
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::fd::{FromRawFd, OwnedFd};

    #[test]
    fn parse_log_max_bytes_handles_overrides_and_fallbacks() {
        use std::ffi::OsStr;
        // Valid positive value is honored (whitespace trimmed).
        assert_eq!(parse_log_max_bytes(Some(OsStr::new("4096"))), 4096);
        assert_eq!(parse_log_max_bytes(Some(OsStr::new("  4096 "))), 4096);
        // Unset, empty, zero, and unparsable all fall back to the default.
        assert_eq!(parse_log_max_bytes(None), DAEMON_LOG_MAX_BYTES);
        assert_eq!(parse_log_max_bytes(Some(OsStr::new(""))), DAEMON_LOG_MAX_BYTES);
        assert_eq!(parse_log_max_bytes(Some(OsStr::new("0"))), DAEMON_LOG_MAX_BYTES);
        assert_eq!(
            parse_log_max_bytes(Some(OsStr::new("not-a-number"))),
            DAEMON_LOG_MAX_BYTES
        );
        assert_eq!(parse_log_max_bytes(Some(OsStr::new("-5"))), DAEMON_LOG_MAX_BYTES);
    }

    #[test]
    fn stop_report_omits_pid_only_when_absent() {
        let json = serde_json::to_string(&StopReport {
            instance: "default",
            pid: None,
            result: "not_running",
        })
        .unwrap();
        assert_eq!(json, r#"{"instance":"default","result":"not_running"}"#);

        let json = serde_json::to_string(&StopReport {
            instance: "work",
            pid: Some(42),
            result: "stopped",
        })
        .unwrap();
        assert_eq!(json, r#"{"instance":"work","pid":42,"result":"stopped"}"#);
    }

    #[test]
    fn rotated_log_path_appends_suffix() {
        assert_eq!(
            rotated_log_path(Path::new("/var/log/ezvpn/ezvpn-client-default.log")),
            PathBuf::from("/var/log/ezvpn/ezvpn-client-default.log.1")
        );
    }

    // Feed more than the cap through the pipe and confirm the writer rotates to
    // a single `.log.1` backup and bounds each file's size.
    #[test]
    fn drain_caps_and_rotates() {
        let dir = std::env::temp_dir().join(format!("ezvpn-logtest-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let log_path = dir.join("ezvpn-client-default.log");

        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read_end = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let mut write_end = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fds[1]) });

        let max_bytes: u64 = 4 * 1024;
        let reader = {
            let path = log_path.clone();
            std::thread::spawn(move || {
                drain_to_capped_log(std::fs::File::from(read_end), &path, max_bytes);
            })
        };

        // Write far more than the pipe buffer (~64KiB) so the reader drains in
        // several 16KiB reads and rotation is exercised (rotation is per-read).
        let chunk = vec![b'x'; 1024];
        for _ in 0..256 {
            write_end.write_all(&chunk).unwrap();
        }
        // Closing the write end signals EOF so the reader thread returns.
        drop(write_end);
        reader.join().unwrap();

        let active = std::fs::metadata(&log_path).expect("active log exists");
        let backup =
            std::fs::metadata(rotated_log_path(&log_path)).expect("rotated backup exists");
        // Each file is bounded by the cap plus at most one buffer chunk.
        let bound = max_bytes + 16 * 1024;
        assert!(active.len() <= bound, "active {} too big", active.len());
        assert!(backup.len() <= bound, "backup {} too big", backup.len());

        let _ = std::fs::remove_dir_all(&dir);
    }

    // When the active log can't be opened (here: the path is a directory), the
    // writer must keep draining the pipe and exit cleanly on EOF rather than
    // returning early and letting the daemon block on a full pipe.
    #[test]
    fn drain_keeps_draining_when_log_unopenable() {
        let dir = std::env::temp_dir().join(format!("ezvpn-logtest2-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        // A directory at the log path makes the file open fail.
        let log_path = dir.join("ezvpn-client-default.log");
        std::fs::create_dir_all(&log_path).unwrap();

        let mut fds = [0 as libc::c_int; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read_end = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let mut write_end = std::fs::File::from(unsafe { OwnedFd::from_raw_fd(fds[1]) });

        let reader = {
            let path = log_path.clone();
            std::thread::spawn(move || drain_to_capped_log(std::fs::File::from(read_end), &path, 1024))
        };

        // More than the pipe buffer: if the writer had returned, these writes
        // would block forever and the join below would hang.
        let chunk = vec![b'x'; 1024];
        for _ in 0..256 {
            write_end.write_all(&chunk).unwrap();
        }
        drop(write_end);
        reader.join().unwrap();

        let _ = std::fs::remove_dir_all(&dir);
    }
}
