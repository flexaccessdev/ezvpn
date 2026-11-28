# win-run.ps1 HOST ROW DIR FLOWS SECS SERVER_IP ROUTER_IP: one wb.ps1 run on the Windows client, over PowerShell remoting.
param([string]$WinHost, [string]$V, [string]$Dir, [int]$Flows = 1, [int]$Secs = 6, [string]$Nt, [string]$Router)
Invoke-Command -HostName $WinHost -SSHTransport -ArgumentList $V, $Dir, $Flows, $Secs, $Nt, $Router -ScriptBlock {
  param($V, $Dir, $Flows, $Secs, $Nt, $Router)
  try { & 'C:\ci-workspaces\ezvpn-bench\run\wb.ps1' -V $V -Dir $Dir -Flows $Flows -Secs $Secs -Nt $Nt -Router $Router 2>&1 | Out-String } catch { "ERROR: $_" }
}
