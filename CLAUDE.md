no backward compatibility at all since it is still 0.0.x.
run cargo clippy and cargo test after making rust code changes.
no cargo fmt

# Design notes
Architecture and design notes live in `docs/Architecture.md`. In particular, see
"Client Isolation" (mandatory server-side client-to-client drop) and "Client
Network Consistency Check (Reconnect)" (how the client handles a reassigned IP vs
other server param changes on reconnect).
