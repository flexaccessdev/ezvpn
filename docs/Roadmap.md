# Roadmap

Work that is planned but not scheduled. Each entry says what the problem is
today and what the change would be.

## Windows: bypass routes through the IP Helper API

On Windows the tunnel's own routes are added and removed with the IP Helper
API (`CreateIpForwardEntry2` / `DeleteIpForwardEntry2`). The underlay bypass
routes are not: the route lookup, the add and the removal each start
`powershell.exe` (`Find-NetRoute`, `New-NetRoute`, `Remove-NetRoute`), at
about 2 s per call.

That slowness is the root of two known weaknesses:

- A bypass route's add keeps running after the session that asked for it is
  gone (it is run to its end so that the route is removed again). If a
  reconnect installed the same route while the old add and its removal were
  still under way, the old cleanup could remove a route the new session is
  using. The reconnect's backoff and its own route lookups keep the two apart
  today.
- Neither the add nor the removal has a deadline. A `powershell.exe` that
  hangs holds up the client's stop, and with it the single-instance lock.

Moving the bypass routes to the IP Helper API, like the tunnel routes, makes
the add immediate, which removes both on Windows, and takes about 2 s off
each connect and each stop that has a bypass route.
