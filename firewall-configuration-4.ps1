# Windows Security Hardening - Minimal & Effective
# Run as Administrator

Write-Host "Windows Security Hardening - Tailscale RDP Only" -ForegroundColor Green

# 1. Check Tailscale
Write-Host "Checking Tailscale..." -ForegroundColor Yellow
$tailscale = @("${env:ProgramFiles}\Tailscale\tailscaled.exe","${env:ProgramFiles(x86)}\Tailscale\tailscaled.exe") | Where-Object {Test-Path $_} | Select-Object -First 1
if (!$tailscale) {
    Write-Host "ERROR: Tailscale not found! Install first." -ForegroundColor Red
    exit 1
}
Write-Host "✓ Tailscale found: $tailscale" -ForegroundColor Green

# 2. Stop critical services
Write-Host "Stopping critical services..." -ForegroundColor Yellow
'LanmanServer','SSDPSRV','upnphost' | ForEach-Object {
    Stop-Service $_ -Force -EA 0
    Set-Service $_ -StartupType Disabled -EA 0
    Write-Host "✓ Disabled $_" -ForegroundColor Green
}

# 3. Disable SMB
Write-Host "Disabling SMB..." -ForegroundColor Yellow
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Force -EA 0
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB2" -Value 0 -Force -EA 0
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -EA 0
Write-Host "✓ SMB disabled" -ForegroundColor Green

# 4. Configure Firewall
Write-Host "Configuring firewall..." -ForegroundColor Yellow
Get-NetFirewallRule | Remove-NetFirewallRule
New-NetFirewallRule -DisplayName "RDP-Tailscale-Only" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress "100.64.0.0/10" -Action Allow
New-NetFirewallRule -DisplayName "System-Loopback" -Direction Inbound -InterfaceAlias "Loopback*" -Action Allow
Set-NetFirewallProfile -All -DefaultInboundAction Block -DefaultOutboundAction Allow
Write-Host "✓ Firewall configured" -ForegroundColor Green

# 5. Restart prompt
Write-Host "`nHardening completed! Press 'q' to quit, any other key to restart..." -ForegroundColor Cyan
$key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown").Character
if ($key -ne 'q') { Restart-Computer -Force }