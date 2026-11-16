//! Process-wide logger setup shared by the CLI and the FFI layers.
//!
//! This is `env_logger` reading `RUST_LOG`, plus one rewrite: the relay
//! rate-limit warning from iroh is reworded (see [`RELAY_RATE_LIMIT_NOTICE`]).

use log::{Level, Log, Metadata, Record, SetLoggerError};

/// Log filter used when `RUST_LOG` is unset. iroh and tracing stay at `warn`:
/// their INFO level logs per-packet spans.
pub const DEFAULT_LOG_FILTER: &str = "info,iroh=warn,tracing=warn";

/// Target and message prefix of iroh's "the relay is rate-limiting this
/// endpoint" warning (`iroh_relay::protos::relay::Status::RateLimited`).
const RELAY_ACTOR_TARGET: &str = "iroh::socket::transports::relay::actor";
const RELAY_RATE_LIMIT_PREFIX: &str = "The relay is rate-limiting this endpoint";

/// What the relay rate-limit warning is logged as instead.
///
/// A relay sends that status once per relay connection, the first time it
/// throttles the endpoint. The public relays do so on the QUIC handshake
/// itself (a few kilobytes), so the warning shows up on every connect, on
/// both ends, whether or not a single tunneled packet ever takes the relay —
/// and its advice ("send less data", "raise Limits::client_rx") is not
/// something an ezvpn user can act on. It only matters while the tunnel has
/// no direct path, so say that in one line. It stays a WARN: on a relay-only
/// tunnel the limit does cap throughput, and at handshake time the two cases
/// cannot be told apart.
const RELAY_RATE_LIMIT_NOTICE: &str = "The relay rate-limits this endpoint's relayed traffic \
     (normal on the public relays); direct paths are unaffected";

fn is_relay_rate_limit_warning(record: &Record) -> bool {
    record.level() == Level::Warn
        && record.target() == RELAY_ACTOR_TARGET
        && record.args().to_string().starts_with(RELAY_RATE_LIMIT_PREFIX)
}

struct Logger {
    inner: env_logger::Logger,
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        self.inner.enabled(metadata)
    }

    fn log(&self, record: &Record) {
        if is_relay_rate_limit_warning(record) {
            // Only the message changes. The level and target stay iroh's, so
            // the inner logger's filter treats this exactly as it would the
            // original: `iroh=error` still silences it and `off,iroh=warn`
            // still shows it.
            self.inner.log(
                &Record::builder()
                    .metadata(record.metadata().clone())
                    .args(format_args!("{RELAY_RATE_LIMIT_NOTICE}"))
                    .module_path(record.module_path())
                    .file(record.file())
                    .line(record.line())
                    .build(),
            );
        } else {
            self.inner.log(record);
        }
    }

    fn flush(&self) {
        self.inner.flush();
    }
}

/// Install the global logger, filtered by `RUST_LOG` (default
/// [`DEFAULT_LOG_FILTER`]) and writing to stderr. Fails if a logger is already
/// installed.
pub fn try_init() -> Result<(), SetLoggerError> {
    let inner = env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or(DEFAULT_LOG_FILTER),
    )
    .build();
    let max_level = inner.filter();
    log::set_boxed_logger(Box::new(Logger { inner }))?;
    log::set_max_level(max_level);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matches(level: Level, target: &str, message: &str) -> bool {
        is_relay_rate_limit_warning(
            &Record::builder()
                .level(level)
                .target(target)
                .args(format_args!("{message}"))
                .build(),
        )
    }

    #[test]
    fn only_the_relay_rate_limit_warning_is_rewritten() {
        let rate_limited = "The relay is rate-limiting this endpoint; outbound relay traffic \
             is being throttled. Send less data over the relay";
        assert!(matches(Level::Warn, RELAY_ACTOR_TARGET, rate_limited));

        // Other relay status reports from the same module keep their WARN.
        assert!(!matches(
            Level::Warn,
            RELAY_ACTOR_TARGET,
            "Relay server reports problem: Another endpoint connected with the same endpoint id."
        ));
        // Same text from anywhere else is left alone.
        assert!(!matches(Level::Warn, "ezvpn::tunnel::client", rate_limited));
        assert!(!matches(Level::Info, RELAY_ACTOR_TARGET, rate_limited));
    }

    /// What a logger with the given `RUST_LOG`-style filter writes for the
    /// relay's rate-limit warning.
    fn rate_limit_output(filters: &str) -> String {
        use std::io::Write;
        use std::sync::{Arc, Mutex};

        #[derive(Clone, Default)]
        struct Sink(Arc<Mutex<Vec<u8>>>);
        impl Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let sink = Sink::default();
        let logger = Logger {
            inner: env_logger::Builder::new()
                .parse_filters(filters)
                .target(env_logger::Target::Pipe(Box::new(sink.clone())))
                .build(),
        };
        logger.log(
            &Record::builder()
                .level(Level::Warn)
                .target(RELAY_ACTOR_TARGET)
                .args(format_args!("{RELAY_RATE_LIMIT_PREFIX}; outbound relay traffic is throttled"))
                .build(),
        );
        let written = sink.0.lock().unwrap().clone();
        String::from_utf8(written).unwrap()
    }

    #[test]
    fn rewritten_notice_respects_the_filter_on_the_original_record() {
        // The notice replaces iroh's wording and stays a warning, under the
        // default filter and under a warnings-only one.
        for filters in [DEFAULT_LOG_FILTER, "warn"] {
            let shown = rate_limit_output(filters);
            assert!(shown.contains("WARN"), "{shown}");
            assert!(shown.contains(RELAY_RATE_LIMIT_NOTICE), "{shown}");
            assert!(!shown.contains(RELAY_RATE_LIMIT_PREFIX), "{shown}");
        }

        // The user silenced iroh's warnings: the rewrite must not bring this
        // one back under ezvpn's own target.
        assert_eq!(rate_limit_output("info,iroh=error"), "");
        assert_eq!(rate_limit_output("error"), "");

        // ...and the reverse: only iroh's warnings were asked for, so this
        // one is still wanted. It keeps iroh's target, which is what lets it
        // through.
        let shown = rate_limit_output("off,iroh=warn");
        assert!(shown.contains(RELAY_RATE_LIMIT_NOTICE), "{shown}");
        assert!(shown.contains(RELAY_ACTOR_TARGET), "{shown}");
    }
}
