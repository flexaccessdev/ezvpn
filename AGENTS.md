no backward compatibility at all since it is still 0.0.x.
run cargo clippy and cargo test after making rust code changes.
no cargo fmt

# Design notes
Architecture and design notes live in `docs/Architecture.md`. In particular, see
"Client Isolation" (mandatory server-side client-to-client drop) and "Client
Network Consistency Check (Reconnect)" (how the client handles a reassigned IP vs
other server param changes on reconnect).

Client authentication uses the shared FlexAccess ed25519 key format from
https://github.com/flexaccessdev/flexaccess-keys (the same one flextunnel uses):
that repo owns the `ed25519-sec:` / `ed25519-pub:` tokens, key files,
authorized-keys parsing, and the `generate-auth-key` / `show-auth-key` CLI.
`src/auth.rs` here owns only ezvpn's domain-separated signing transcript
(`ezvpn-client-auth-v1`) and the authorization decision. Do not add key
generation to the ezvpn CLI.

The iroh transport layer shared with tunnel-rs and flextunnel — relays and
address lookup, the per-relay startup probe, relay auth tokens, relay
self-hosting — is documented once in
https://github.com/flexaccessdev/iroh-common-architecture. Do not duplicate it in
this repo; update it there and link to it.

That shared layer's code — `RelayConfig` and the relay probe, endpoint
building and rebuild, the home-relay watchdog, the endpoint-bound auth
transcript — lives in the `flexaccess-iroh` crate (`../flexaccess-iroh`,
consumed by git tag). Fix it there, tag a release, and bump the tag here; never
re-implement or fork a copy of it in this repo. Only ezvpn-specific pieces (the
VPN ALPN, QUIC transport tuning, the auth context, the bounded connect, key
files) belong in `src/transport/` and `src/auth.rs`. ezvpn depends on forks of
iroh, noq (noq, noq-proto, noq-udp) and netwatch, all under the `flexaccessdev`
org (clones in `../iroh`, `../noq`, `../net-tools`), one `ezvpn-*` branch each
on top of the upstream release. They are applied through `[patch.crates-io]` in
`Cargo.toml` rather than as git dependencies, so that every crate in the graph,
the shared crate's `iroh` included, resolves to them. Fix transport-stack bugs
on those branches and bump `Cargo.lock` here; the `Cargo.toml` comments say what
each fork carries.

The mobile apps live in sibling repos: `../ezvpn-apple` (Swift, see
`docs/Apple-App.md`) and `../ezvpn-android` (Kotlin, see `docs/Android-App.md`).
Both drive the fd-based `MobileSession` in `src/tunnel/mobile.rs` through
`src/ffi.rs`; Android adds the JNI layer `src/ffi_android.rs`, whose symbol
names are bound to the Kotlin class `dev.flexaccess.ezvpn.EzvpnNative` — do not
rename either side alone. The in-tunnel split-DNS forwarder
(`src/tunnel/dns_proxy.rs`) is an Android-only workaround for the platform
having no per-domain VPN DNS; every other platform keeps OS-level conditional
forwarding, so never wire it up elsewhere. Verify Android changes with
`cargo ndk -t arm64-v8a --platform 29 clippy --lib -- -D warnings` (the module
is cfg-gated out of the host clippy).
