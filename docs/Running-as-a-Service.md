# Running the VPN client as a service

`ezvpn client start` is a **foreground** process: it logs to stdout/stderr and
runs until stopped. The recommended way to run it unattended is to let your
platform's service manager handle backgrounding, restart-on-crash, start-at-boot,
and log capture.

For a quick background run without a service manager, `client start --daemon`
(Unix only) forks into the background and logs to
`<log_dir>/ezvpn-client-<instance>.log` — the persistent log directory
(`/var/log/ezvpn` on Linux and macOS), created owner-only on first run and
overridable with `EZVPN_LOG_DIR`. This log is size-capped: it rotates to a
single `<name>.log.1` backup at 10 MiB (override the cap in bytes with
`EZVPN_LOG_MAX_BYTES`), bounding disk use at ~20 MiB per instance. (Under a
service manager the foreground form is used instead, and the
service manager handles log capture and rotation — see below.) Stop it with the
**same** `--instance` it was started with, e.g.:

```bash
sudo ezvpn client start --daemon -c /etc/ezvpn/work.toml --instance work
sudo ezvpn client stop --instance work    # omit --instance for the "default" instance
```

A service manager is still preferred for unattended deployments because it
handles restart-on-crash and start-at-boot; use the **foreground** form under a
service manager (let it own backgrounding), not `--daemon`.

These examples cover the **client**. The server uses the same service-manager
pattern with `ezvpn server start -c ...`; it has no `--instance` flag and uses
the fixed `default` instance for `server status` / `server list`. The macOS
and Windows sections each have a worked server example
([launchd](#server), [NSSM](#server-nssm)).

> The tunnel creates a TUN device and edits the routing table, so the service
> must run with administrative privileges (root / LocalSystem).

## A note on the runtime directory (`status` / `list` / Unix `stop`)

`ezvpn` keeps its per-instance lock file in a **fixed, machine-global runtime
directory**: `/run/ezvpn` on Linux, `/var/run/ezvpn` on macOS, and
`%ProgramData%\ezvpn` on Windows. Unix control sockets also live in that
runtime directory; Windows uses global named pipes such as
`\\.\pipe\ezvpn-client-work`. The directory is created on first run
(world-traversable, `0755`, on Unix — the control sockets inside are read-only
and world-connectable so `status`/`list` work without sudo). It holds runtime
state — on Linux `/run` is tmpfs and cleared on reboot. (The
`--daemon` log file is kept separately under the persistent log directory; see
above. The service-manager setups below run in the foreground and capture logs
via the service manager, so they don't use it.)

Because the runtime location and control endpoint names are fixed, `status` /
`list` and Unix `stop` resolve the same instance no matter how the service was
started. `status` / `list` need no elevation (a daemon started by an older
ezvpn version keeps its restrictive permissions until restarted); run Unix
`stop` with `sudo`. Set `EZVPN_RUNTIME_DIR` only if you need a non-default
location (e.g. containers or a rootless deployment); if you do, set it
identically for the service and for the commands you type by hand.

---

## Linux — systemd

systemd template units map cleanly onto `--instance`: `%i` is the instance name,
so one unit file serves every instance.

`/etc/systemd/system/ezvpn-client@.service`:

```ini
[Unit]
Description=ezvpn client (%i)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/ezvpn client start -c /etc/ezvpn/%i.toml --instance %i
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Install and manage (instance `work` reads `/etc/ezvpn/work.toml`):

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now ezvpn-client@work     # start now + at boot
sudo systemctl status      ezvpn-client@work
sudo journalctl -u ezvpn-client@work -f           # follow logs
sudo systemctl restart     ezvpn-client@work
sudo systemctl disable --now ezvpn-client@work    # stop + remove from boot
```

App-level status / listing (no sudo needed):

```bash
ezvpn client status --instance work
ezvpn client list
```

Run a second instance by starting another copy of the template:

```bash
sudo systemctl enable --now ezvpn-client@home     # reads /etc/ezvpn/home.toml
```

---

## macOS — launchd

launchd has no template units, so use **one plist per instance** — copy the file
and change `Label`, the config path, `--instance`, and the log path.

`/Library/LaunchDaemons/com.ezvpn.client.work.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ezvpn.client.work</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/ezvpn</string>
        <string>client</string>
        <string>start</string>
        <string>-c</string>
        <string>/usr/local/etc/ezvpn/work.toml</string>
        <string>--instance</string>
        <string>work</string>
    </array>

    <key>RunAtLoad</key><true/>

    <!-- restart on crash, but not after a clean exit -->
    <key>KeepAlive</key>
    <dict><key>SuccessfulExit</key><false/></dict>

    <!-- launchd has no journald; capture logs to files -->
    <key>StandardOutPath</key><string>/var/log/ezvpn-work.log</string>
    <key>StandardErrorPath</key><string>/var/log/ezvpn-work.log</string>
</dict>
</plist>
```

Install and manage (modern `launchctl`, macOS 10.11+):

```bash
# launchd rejects plists that aren't root-owned or are writable by others
sudo chown root:wheel /Library/LaunchDaemons/com.ezvpn.client.work.plist
sudo chmod 644        /Library/LaunchDaemons/com.ezvpn.client.work.plist

sudo launchctl bootstrap system /Library/LaunchDaemons/com.ezvpn.client.work.plist
sudo launchctl print     system/com.ezvpn.client.work     # inspect
sudo launchctl kickstart -k system/com.ezvpn.client.work  # restart
sudo launchctl bootout   system/com.ezvpn.client.work     # stop + unload
```

App-level status / listing (no sudo needed):

```bash
ezvpn client status --instance work
ezvpn client list
```

### Default instance (no `--instance`)

If you only run one client, use the `default` instance: drop the `--instance`
flag entirely (omitting it *is* `default`) and drop it from `status` too.

`/Library/LaunchDaemons/com.ezvpn.client.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ezvpn.client</string>

    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/ezvpn</string>
        <string>client</string>
        <string>start</string>
        <string>-c</string>
        <string>/usr/local/etc/ezvpn/vpn_client.toml</string>
        <!-- no --instance: this is the "default" instance -->
    </array>

    <key>RunAtLoad</key><true/>

    <!-- restart on crash, but not after a clean exit -->
    <key>KeepAlive</key>
    <dict><key>SuccessfulExit</key><false/></dict>

    <!-- launchd has no journald; capture logs to files -->
    <key>StandardOutPath</key><string>/var/log/ezvpn.log</string>
    <key>StandardErrorPath</key><string>/var/log/ezvpn.log</string>
</dict>
</plist>
```

Install and manage (same as above, with the shorter label):

```bash
sudo chown root:wheel /Library/LaunchDaemons/com.ezvpn.client.plist
sudo chmod 644        /Library/LaunchDaemons/com.ezvpn.client.plist

sudo launchctl bootstrap system /Library/LaunchDaemons/com.ezvpn.client.plist
sudo launchctl print     system/com.ezvpn.client     # inspect
sudo launchctl kickstart -k system/com.ezvpn.client  # restart
sudo launchctl bootout   system/com.ezvpn.client     # stop + unload
```

App-level status / listing (no sudo needed; no `--instance` queries the
default instance):

```bash
ezvpn client status
ezvpn client list
```

### Server

A host runs one server, so there is one plist and no `--instance`.

Keep the config, the server key, and the authorized-keys file together in the
system config directory, readable by root only:

```bash
sudo install -d -m 700 /usr/local/etc/ezvpn
sudo ezvpn generate-server-key --output /usr/local/etc/ezvpn/vpn-server.key
# then put vpn_server.toml and authorized_keys in the same directory
```

Use absolute paths inside `vpn_server.toml`. launchd starts the job with `/`
as its working directory, and a relative `secret_file` or
`authorized_keys_file` is resolved against the working directory, not against
the config file:

```toml
[auth]
authorized_keys_file = "/usr/local/etc/ezvpn/authorized_keys"

[iroh]
secret_file = "/usr/local/etc/ezvpn/vpn-server.key"
```

`/Library/LaunchDaemons/com.ezvpn.server.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.ezvpn.server</string>

    <key>ProgramArguments</key>
    <array>
        <string>/bin/sh</string>
        <string>-c</string>
        <!-- 2>&1 | sed | logger: every line goes to unified logging, prefixed -->
        <string>/usr/local/bin/ezvpn server start -c /usr/local/etc/ezvpn/vpn_server.toml 2&gt;&amp;1 | /usr/bin/sed -l 's/^/ezvpn-server: /' | /usr/bin/logger</string>
    </array>

    <key>RunAtLoad</key><true/>

    <!-- the shell's exit status is logger's, not ezvpn's: always restart -->
    <key>KeepAlive</key><true/>
</dict>
</plist>
```

The job is a shell pipeline rather than `ezvpn` itself, so that the server's
output goes to macOS unified logging instead of a file that nothing rotates
(see [Logs](#logs)). Two things follow from the pipeline:

- `KeepAlive` is a plain `true`. launchd sees the exit status of the shell,
  which is `logger`'s and is `0` even when `ezvpn` crashed, so the
  `SuccessfulExit` form used for the client would never restart it.
- launchd signals the shell, not `ezvpn`. That is fine for the server, which
  has no shutdown work to do.

Install and manage:

```bash
sudo chown root:wheel /Library/LaunchDaemons/com.ezvpn.server.plist
sudo chmod 644        /Library/LaunchDaemons/com.ezvpn.server.plist

sudo launchctl bootstrap system /Library/LaunchDaemons/com.ezvpn.server.plist
sudo launchctl print     system/com.ezvpn.server     # inspect
sudo launchctl kickstart -k system/com.ezvpn.server  # restart
sudo launchctl bootout   system/com.ezvpn.server     # stop + unload
```

There is no `ezvpn server stop`: stop the server with `launchctl bootout`. To
upgrade, move the new binary into place at `/usr/local/bin/ezvpn` (do not copy
over the running one, which can get the process killed) and restart the job
with `kickstart -k`.

App-level status / listing (no sudo needed):

```bash
ezvpn server status   # includes the Node ID that clients connect to
ezvpn server list
```

### Logs

launchd has no journald. It can only append a job's output to the
`StandardOutPath` file, and it never rotates that file.

The server plist above avoids the file: it pipes the output through
`/usr/bin/logger` into unified logging, which caps and rotates its own store.
Each line is prefixed with `ezvpn-server: ` on the way, because the tag given
with `logger -t` does not show up in unified logging and the lines would
otherwise be indistinguishable from any other `logger` output. Read them with
`log` (`/usr/bin/log` in zsh, where `log` is a builtin):

```bash
P='process == "logger" AND eventMessage BEGINSWITH "ezvpn-server: "'
/usr/bin/log show --last 1h --predicate "$P" --style compact   # recent
/usr/bin/log stream --predicate "$P" --style compact           # follow
```

The client plists write to a file instead. The client is launched directly so
that `launchctl bootout` delivers its `SIGTERM` to `ezvpn`, which then shuts
the tunnel down cleanly; behind a shell pipeline the signal would go to the
shell. With the default logging the file grows slowly (startup, connects and
disconnects, warnings). It is opened in append mode, so it can be emptied in
place without restarting the job:

```bash
sudo sh -c ': > /var/log/ezvpn-work.log'
```

Leave `RUST_LOG` out of the plist unless you are debugging. Unset, the filter
is `info,iroh=warn,tracing=warn`: ezvpn's own events at `info`, with the iroh
transport held at `warn`. A plain `RUST_LOG=info` replaces that whole filter,
which lifts iroh to `info` as well, and iroh logs individual packets at that
level: a mostly idle server left that way wrote about 1.6 GB to its log file
in under three weeks.

---

## Windows — Windows Service

`ezvpn.exe` is a normal console program; it does not implement the Service
Control Protocol, so `sc.exe create` pointed straight at it will fail to start
(the SCM times out waiting for it to report running). Use a small **service
wrapper** that runs an arbitrary console program as a service. The two common
choices are [NSSM](https://nssm.cc/) and
[WinSW](https://github.com/winsw/winsw); NSSM is shown here.

> Prerequisite: `wintun.dll` from [WinTun](https://www.wintun.net/) must be
> available next to `ezvpn.exe` or in the system `PATH` (see the project
> README). The service runs as **LocalSystem** (administrator), which can create
> the TUN adapter.

Install and manage one service per instance (run from an elevated PowerShell):

```powershell
$exe = "$env:ProgramData\ezvpn\ezvpn.exe"

nssm install ezvpn-work $exe client start -c "C:\ProgramData\ezvpn\work.toml" --instance work

# Logs (NSSM redirects the console output). NSSM does not create the
# directory, and the service will not start without it.
New-Item -ItemType Directory -Force C:\ProgramData\ezvpn\logs | Out-Null
nssm set ezvpn-work AppStdout C:\ProgramData\ezvpn\logs\work.log
nssm set ezvpn-work AppStderr C:\ProgramData\ezvpn\logs\work.log
nssm set ezvpn-work Start SERVICE_AUTO_START

nssm start   ezvpn-work
nssm restart ezvpn-work
nssm stop    ezvpn-work
nssm remove  ezvpn-work confirm   # uninstall
```

App-level status / listing (no elevation needed — the pipe is opened
read-only, which its default ACL grants to everyone):

```powershell
# status uses the global named pipe \\.\pipe\ezvpn-client-work; list scans
# lock files in the fixed runtime dir (%ProgramData%\ezvpn).
ezvpn client status --instance work
ezvpn client list
```

### Default instance (no `--instance`)

For a single client, use the `default` instance — omit `--instance` when
creating the service and when querying it:

```powershell
$exe = "$env:ProgramData\ezvpn\ezvpn.exe"

# no --instance: this is the "default" instance
nssm install ezvpn $exe client start -c "C:\ProgramData\ezvpn\vpn_client.toml"

# Logs (NSSM redirects the console output). NSSM does not create the
# directory, and the service will not start without it.
New-Item -ItemType Directory -Force C:\ProgramData\ezvpn\logs | Out-Null
nssm set ezvpn AppStdout C:\ProgramData\ezvpn\logs\client.log
nssm set ezvpn AppStderr C:\ProgramData\ezvpn\logs\client.log
nssm set ezvpn Start SERVICE_AUTO_START

nssm start   ezvpn
nssm restart ezvpn
nssm stop    ezvpn
nssm remove  ezvpn confirm   # uninstall
```

App-level status / listing (no elevation needed; no `--instance` queries the
default instance):

```powershell
# status uses the global named pipe \\.\pipe\ezvpn-client-default; list scans
# lock files in the fixed runtime dir (%ProgramData%\ezvpn).
ezvpn client status
ezvpn client list
```

A lighter alternative to a wrapper is **Task Scheduler**: create a task that runs
`ezvpn.exe client start ...` "At startup", "Run whether user is logged on or
not", with "Run with highest privileges". You lose automatic crash-restart and
clean log capture, so a service wrapper is preferred for production.

### Server (NSSM)

A host runs one server, so there is one service and no `--instance`. This
assumes `ezvpn.exe` was installed by the installer into `%ProgramData%\ezvpn`
with `wintun.dll` beside it, and that NSSM is installed (for example
`winget install NSSM.NSSM`). Run everything from an elevated PowerShell.

**Files.** Keep the config, the server key, and the authorized-keys file in
`%ProgramData%\ezvpn`, and create the log directory (NSSM does not):

```powershell
$dir = "$env:ProgramData\ezvpn"
ezvpn generate-server-key --output "$dir\vpn-server.key"
# then put vpn_server.toml and authorized_keys in $dir
New-Item -ItemType Directory -Force "$dir\logs" | Out-Null
```

Use absolute paths inside `vpn_server.toml`, in single quotes so that TOML
does not read the backslashes as escapes:

```toml
[auth]
authorized_keys_file = 'C:\ProgramData\ezvpn\authorized_keys'

[iroh]
secret_file = 'C:\ProgramData\ezvpn\vpn-server.key'
```

**Permissions.** The installer leaves `%ProgramData%\ezvpn` writable by SYSTEM
and Administrators only. Other local users can still read it, which is what
lets `ezvpn server status` and `ezvpn server list` run without elevation. The
server key should not be readable by them, so take it out of that:

```powershell
# S-1-5-18 = SYSTEM, S-1-5-32-544 = Administrators
# (SIDs, so the command also works on a non-English Windows).
icacls "$dir\vpn-server.key" /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F"
```

**Service.**

```powershell
nssm install ezvpn-server "$dir\ezvpn.exe" server start -c "$dir\vpn_server.toml"
nssm set ezvpn-server Start SERVICE_AUTO_START

# Logs: ezvpn logs to stderr
nssm set ezvpn-server AppStderr "$dir\logs\server.log"
nssm set ezvpn-server AppRotateFiles 1
nssm set ezvpn-server AppRotateOnline 1
nssm set ezvpn-server AppRotateBytes 10485760

nssm start   ezvpn-server
nssm restart ezvpn-server
nssm stop    ezvpn-server
nssm remove  ezvpn-server confirm   # uninstall
```

There is no `ezvpn server stop`: stop the server with `nssm stop`. NSSM
restarts the server if it exits, and the service starts at boot before anyone
logs in.

With those log settings NSSM starts a fresh `server.log` each time the service
starts and keeps the previous one as `server-<timestamp>.log`. While the
service runs it rotates the same way once the file passes `AppRotateBytes`
(10 MiB here). Nothing deletes the old files.

Redirect `AppStderr` only. Pointing `AppStdout` at the same file together with
`AppRotateOnline` left the service stuck in "stop pending" on `nssm stop` when
tested with NSSM 2.24-101.

App-level status / listing (no elevation needed):

```powershell
ezvpn server status   # includes the Node ID that clients connect to
ezvpn server list
```

**Windows Firewall.** `ezvpn` itself needs no inbound rule. Traffic from
clients to the server host is a different matter: the tunnel adapter comes up
in the Public profile, so Windows Firewall drops what clients send to the
server's VPN IP, pings and services alike. The adapter is created anew on
every start, so write the rule against the VPN prefix (the server config's
`network`) and not against the adapter:

```powershell
# everything from VPN clients
New-NetFirewallRule -DisplayName "ezvpn clients" -Direction Inbound -Action Allow -RemoteAddress 10.0.0.0/24

# or one service only, e.g. Remote Desktop
New-NetFirewallRule -DisplayName "ezvpn clients RDP" -Direction Inbound -Action Allow -RemoteAddress 10.0.0.0/24 -Protocol TCP -LocalPort 3389
```

**Upgrading.** Stop the service, run the installer again, and start the
service.

This covers reaching the Windows host itself at its VPN IP. Making it a
gateway to the rest of its network (forwarding and NAT) is not documented
yet; [Server-Site-Gateway.md](Server-Site-Gateway.md) has that setup for Linux.

---

## Multiple instances

On every platform, each running client is identified by `--instance <NAME>`
(default `default`) and gets its own lock file and control endpoint. Because all
instances share the one fixed runtime directory for lock discovery,
`ezvpn client list` shows them together. Lock files are left behind on exit, so
a stopped instance may briefly show as `not responding (stale lock)` until its
lock is reused.
