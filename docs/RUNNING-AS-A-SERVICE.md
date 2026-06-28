# Running the VPN client as a service

`ezvpn client start` is a **foreground** process: it logs to stdout/stderr and
runs until stopped. The recommended way to run it unattended is to let your
platform's service manager handle backgrounding, restart-on-crash, start-at-boot,
and log capture.

For a quick background run without a service manager, `client start --daemon`
(Unix only) forks into the background and logs to
`<log_dir>/ezvpn-client-<instance>.log` — the persistent log directory
(`/var/log/ezvpn` on Linux and macOS), created owner-only on first run and
overridable with `EZVPN_LOG_DIR`. Stop it with the **same** `--instance` it was
started with, e.g.:

```bash
sudo ezvpn client start --daemon -c /etc/ezvpn/work.toml --instance work
sudo ezvpn client stop --instance work    # omit --instance for the "default" instance
```

A service manager is still preferred for unattended deployments because it
handles restart-on-crash and start-at-boot; use the **foreground** form under a
service manager (let it own backgrounding), not `--daemon`.

These examples cover the **client**. The server uses the same service-manager
pattern with `ezvpn server start -c ...`; it has no `--instance` flag and uses
the fixed `default` instance for `server status` / `server list`.

> The tunnel creates a TUN device and edits the routing table, so the service
> must run with administrative privileges (root / LocalSystem).

## A note on the runtime directory (`status` / `list` / Unix `stop`)

`ezvpn` keeps its per-instance lock file and control socket in a **fixed,
machine-global runtime directory**: `/run/ezvpn` on Linux, `/var/run/ezvpn` on
macOS, and `%ProgramData%\ezvpn` on Windows. It is created (owner-only) on first run. This directory holds only
ephemeral state — on Linux `/run` is tmpfs and cleared on reboot. (The
`--daemon` log file is kept separately under the persistent log directory; see
above. The service-manager setups below run in the foreground and capture logs
via the service manager, so they don't use it.)

Because the runtime location is fixed and the daemon runs as root, `status` /
`list` and Unix `stop` resolve the same place no matter how the service was
started. Run `status` / `list` elevated (`sudo` or Administrator), and run Unix
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
Environment=RUST_LOG=info

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

App-level status / listing:

```bash
sudo ezvpn client status --instance work
sudo ezvpn client list
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

    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key><string>info</string>
    </dict>

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

App-level status / listing:

```bash
sudo ezvpn client status --instance work
sudo ezvpn client list
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

    <key>EnvironmentVariables</key>
    <dict>
        <key>RUST_LOG</key><string>info</string>
    </dict>

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

App-level status / listing (no `--instance` queries the default instance):

```bash
sudo ezvpn client status
sudo ezvpn client list
```

---

## Windows — Windows Service

`ezvpn.exe` is a normal console program; it does not implement the Service
Control Protocol, so `sc.exe create` pointed straight at it will fail to start
(the SCM times out waiting for it to report running). Use a small **service
wrapper** that runs an arbitrary console program as a service. The two common
choices are [NSSM](https://nssm.cc/) and
[WinSW](https://github.com/winsw/winsw); NSSM is shown here.

> Prerequisite: the [WinTun](https://www.wintun.net/) driver must be installed
> (see the project README). The service runs as **LocalSystem** (administrator),
> which can create the TUN adapter.

Install and manage one service per instance (run from an elevated PowerShell):

```powershell
$exe = "C:\Program Files\ezvpn\ezvpn.exe"

nssm install ezvpn-work $exe client start -c "C:\ProgramData\ezvpn\work.toml" --instance work

nssm set ezvpn-work AppEnvironmentExtra RUST_LOG=info

# Logs (NSSM redirects the console output)
nssm set ezvpn-work AppStdout C:\ProgramData\ezvpn\logs\work.log
nssm set ezvpn-work AppStderr C:\ProgramData\ezvpn\logs\work.log
nssm set ezvpn-work Start SERVICE_AUTO_START

nssm start   ezvpn-work
nssm restart ezvpn-work
nssm stop    ezvpn-work
nssm remove  ezvpn-work confirm   # uninstall
```

App-level status / listing (from an elevated shell):

```powershell
# status uses the global named pipe \\.\pipe\ezvpn-client-work; list scans
# lock files in the fixed runtime dir (%ProgramData%\ezvpn). Run elevated.
ezvpn client status --instance work
ezvpn client list
```

### Default instance (no `--instance`)

For a single client, use the `default` instance — omit `--instance` when
creating the service and when querying it:

```powershell
$exe = "C:\Program Files\ezvpn\ezvpn.exe"

# no --instance: this is the "default" instance
nssm install ezvpn $exe client start -c "C:\ProgramData\ezvpn\vpn_client.toml"

nssm set ezvpn AppEnvironmentExtra RUST_LOG=info

# Logs (NSSM redirects the console output)
nssm set ezvpn AppStdout C:\ProgramData\ezvpn\logs\client.log
nssm set ezvpn AppStderr C:\ProgramData\ezvpn\logs\client.log
nssm set ezvpn Start SERVICE_AUTO_START

nssm start   ezvpn
nssm restart ezvpn
nssm stop    ezvpn
nssm remove  ezvpn confirm   # uninstall
```

App-level status / listing (no `--instance` queries the default instance):

```powershell
# status uses the global named pipe \\.\pipe\ezvpn-client-default; list scans
# lock files in the fixed runtime dir (%ProgramData%\ezvpn). Run elevated.
ezvpn client status
ezvpn client list
```

A lighter alternative to a wrapper is **Task Scheduler**: create a task that runs
`ezvpn.exe client start ...` "At startup", "Run whether user is logged on or
not", with "Run with highest privileges". You lose automatic crash-restart and
clean log capture, so a service wrapper is preferred for production.

---

## Multiple instances

On every platform, each running client is identified by `--instance <NAME>`
(default `default`) and gets its own lock file and control socket. Because all
instances share the one fixed runtime directory, `ezvpn client list` shows them
together. Lock files are left behind on exit, so a stopped instance may briefly
show as `not responding (stale lock)` until its lock is reused.
