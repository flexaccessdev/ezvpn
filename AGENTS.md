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
iroh, noq (noq, noq-proto, noq-udp), netwatch and netdev, all under the
`flexaccessdev` org (clones in `../iroh`, `../noq`, `../net-tools`, `../netdev`),
one `ezvpn-*` branch each
on top of the upstream release. They are applied through `[patch.crates-io]` in
`Cargo.toml` rather than as git dependencies, so that every crate in the graph,
the shared crate's `iroh` included, resolves to them. Fix transport-stack bugs
on those branches and bump `Cargo.lock` here; the `Cargo.toml` comments say what
each fork carries.

The Apple app lives in the sibling repo `../ezvpn-apple` (Swift, see
`docs/Apple-App.md`) and drives the fd-based `MobileSession` in
`src/tunnel/mobile.rs` through `src/ffi.rs`. Android support is dropped for now
(the `../ezvpn-android` app is on hold); the JNI layer and its in-tunnel
split-DNS forwarder were removed, and git history has them if it comes back.
