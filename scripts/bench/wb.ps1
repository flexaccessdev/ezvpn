# wb.ps1 ROW DIR FLOWS [SECS]: one benchmark run on the Windows client, printed as one JSON line.
# ROW is none (no tunnel) or the suffix of an ezvpn-<ROW>.exe here.
param([string]$V, [string]$Dir, [int]$Flows = 1, [int]$Secs = 6, [string]$Nt, [string]$Router)
$ErrorActionPreference = 'Stop'
$B = 'C:\ci-workspaces\ezvpn-bench\run'
Set-Location $B
$Id = (Get-Content "$B\server_id" -Raw).Trim()

function Run-Iperf([string]$TargetHost) {
  for ($a = 0; $a -lt 3; $a++) {
    $ia = @('-J', '-t', "$Secs", '-O', '1', '-P', "$Flows", '-c', $TargetHost)
    if ($Dir -eq 'down') { $ia += '-R' }
    $out = (& "$B\iperf3.exe" @ia 2>&1 | Out-String)
    try {
      $j = $out | ConvertFrom-Json
      if ($j.end.sum_received) {
        return @{ mbps = [math]::Round($j.end.sum_received.bits_per_second / 1e6, 1); retr = $j.end.sum_sent.retransmits }
      }
    } catch {}
    Start-Sleep 2
  }
  throw "iperf3 failed: $out"
}

if ($V -eq 'none') {
  Run-Iperf $Nt | ConvertTo-Json -Compress
  return
}

$exe = "$B\ezvpn-$V.exe"
function Conn { ((& $exe client status 2>&1 | Out-String) -split "`n" | Where-Object { $_ -match '^Connection:' }) -replace '^Connection:\s*', '' | ForEach-Object { $_.Trim() } }
Get-Process "ezvpn-*" -ErrorAction SilentlyContinue | Stop-Process -Force
Remove-Item "$B\client.out", "$B\client.err" -ErrorAction SilentlyContinue
$env:RUST_LOG = 'warn,ezvpn=info'
# IPv6 and the router's public address are kept off the direct path, so every run is IPv4 to the server's own address.
$p = Start-Process -FilePath $exe -WorkingDirectory $B -WindowStyle Hidden -PassThru `
  -RedirectStandardOutput "$B\client.out" -RedirectStandardError "$B\client.err" `
  -ArgumentList @('client', 'start', '-n', $Id, '--auth-key-file', "$B\client.key",
    '--exclude-direct-path', '100.64.0.0/10',
    '--exclude-direct-path', '::/0', '--exclude-direct-path', "$Router/32")
try {
  $ok = $false
  for ($i = 0; $i -lt 40; $i++) {
    if (Test-Connection 10.77.0.1 -Count 1 -TimeoutSeconds 1 -Quiet) { $ok = $true; break }
    Start-Sleep -Milliseconds 300
  }
  if (-not $ok) { throw "no ping: $(Get-Content "$B\client.err" -Tail 5 | Out-String)" }
  Start-Sleep 5
  $path = Conn
  $p.Refresh(); $c0 = $p.TotalProcessorTime.TotalSeconds; $t0 = Get-Date
  $r = Run-Iperf '10.77.0.1'
  $p.Refresh(); $c1 = $p.TotalProcessorTime.TotalSeconds; $t1 = Get-Date
  $ver = (Select-String -Path "$B\client.err", "$B\client.out" -Pattern 'ezvpn v[0-9.]+' | Select-Object -First 1).Matches.Value
  $r.secs = [math]::Round(($t1 - $t0).TotalSeconds, 3)
  $r.cpu_client = [math]::Round(($c1 - $c0) / ($t1 - $t0).TotalSeconds, 2)
  $r.path = "$path"
  $r.path_after = "$(Conn)"
  $r.version = $ver
  $r | ConvertTo-Json -Compress
} finally {
  if (-not $p.HasExited) { Stop-Process -Id $p.Id -Force; $p.WaitForExit(5000) | Out-Null }
}
