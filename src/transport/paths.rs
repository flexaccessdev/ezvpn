//! Connection path reporting (direct vs relay).
//!
//! Logs the currently selected iroh connection path(s) with RTT and logs
//! again whenever the selected path changes (e.g., relay -> direct).

use futures::StreamExt;
use iroh::TransportAddr;
use iroh::endpoint::{Connection, PathList};
use tokio::task::JoinHandle;

/// Format connection path info for display, showing *all* paths with RTT and
/// marking which is selected.
///
/// All paths are listed (not just the selected one) so a direct path that iroh
/// has discovered but not selected — e.g. when direct-path bypass is disabled
/// and the direct path is self-captured into the tunnel — is still visible in
/// `ezvpn client status` and the `Connection:` log line.
pub fn format_connection_paths(paths: &PathList<'_>) -> String {
    if paths.is_empty() {
        return "establishing...".to_string();
    }
    let parts: Vec<String> = paths
        .iter()
        .map(|path| {
            let rtt = path.rtt();
            let sel = if path.is_selected() { " (selected)" } else { "" };
            match path.remote_addr() {
                TransportAddr::Ip(addr) => format!("Direct {}{} (rtt {:.0?})", addr, sel, rtt),
                TransportAddr::Relay(url) => format!("Relay {}{} (rtt {:.0?})", url, sel, rtt),
                other => format!("{:?}{} (rtt {:.0?})", other, sel, rtt),
            }
        })
        .collect();
    if parts.is_empty() {
        "no paths".to_string()
    } else {
        parts.join(", ")
    }
}

/// Key identifying the full path topology (all paths plus which is selected),
/// excluding the volatile RTT, so we only log when the path set actually
/// changes — including when a non-selected direct candidate appears or goes.
fn paths_key(paths: &PathList<'_>) -> (bool, Vec<String>) {
    let all = paths
        .iter()
        .map(|p| format!("{:?}{}", p.remote_addr(), if p.is_selected() { "*" } else { "" }))
        .collect();
    (paths.is_empty(), all)
}

/// RAII guard that aborts the background path watcher task on drop.
pub struct PathWatcherGuard(JoinHandle<()>);

impl Drop for PathWatcherGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Log the current connection path and spawn a background task that logs
/// updates whenever the selected path changes (e.g., relay -> direct).
///
/// The returned [`PathWatcherGuard`] aborts the background task when dropped.
/// Callers must keep the guard alive for the duration of the connection.
pub fn watch_connection_paths(connection: &Connection, label: &str) -> PathWatcherGuard {
    let connection = connection.clone();
    let label = label.to_string();
    PathWatcherGuard(tokio::spawn(async move {
        // The stream yields the current snapshot on the first poll, then a
        // fresh snapshot whenever the open or selected paths change; it ends
        // when the connection closes.
        let mut stream = connection.paths_stream();
        let mut last_key = None;
        while let Some(paths) = stream.next().await {
            let key = paths_key(&paths);
            if last_key.as_ref() != Some(&key) {
                log::info!("{}: {}", label, format_connection_paths(&paths));
                last_key = Some(key);
            }
        }
    }))
}
