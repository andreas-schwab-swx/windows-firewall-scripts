# Windows Maximum Security - Tailscale + RDP only
# Run as Administrator

# Remove all rules & set strict defaults
Get-NetFirewallRule | Remove-NetFirewallRule
Set-NetFirewallProfile -All -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Block

# Essential system
New-NetFirewallRule -DisplayName "Loopback" -Direction Inbound -InterfaceAlias "Loopback*" -Action Allow
New-NetFirewallRule -DisplayName "DHCP" -Direction Inbound -Protocol UDP -LocalPort 68 -Action Allow
New-NetFirewallRule -DisplayName "DNS-Out" -Direction Outbound -Protocol UDP -RemoteAddress "1.1.1.1","1.0.0.1" -RemotePort 53 -Action Allow

# Tailscale
$ts = @("${env:ProgramFiles}\Tailscale\tailscaled.exe","${env:ProgramFiles(x86)}\Tailscale\tailscaled.exe") | Where-Object {Test-Path $_} | Select-Object -First 1
if ($ts) { New-NetFirewallRule -DisplayName "Tailscale" -Program $ts -Action Allow }
New-NetFirewallRule -DisplayName "Tailscale-Net" -RemoteAddress "100.64.0.0/10" -Action Allow
New-NetFirewallRule -DisplayName "Tailscale-Coord" -Direction Outbound -Protocol TCP -RemoteAddress "20.189.173.2" -RemotePort 443 -Action Allow

# RDP (only from Tailscale network)
New-NetFirewallRule -DisplayName "RDP-Tailscale-Only" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress "100.64.0.0/10" -Action Allow

# Windows Update
New-NetFirewallRule -DisplayName "WinUpdate" -Direction Outbound -Protocol TCP -RemoteAddress "13.107.42.14","40.119.211.203" -RemotePort 80,443 -Action Allow

# Disable dangerous services
'LanmanServer','SSDPSRV','upnphost','WMPNetworkSvc','XboxNetApiSvc','DsSvc','CDPSvc','DiagTrack','RemoteRegistry','SharedAccess' | ForEach-Object {
    Stop-Service $_ -Force -EA 0; Set-Service $_ -StartupType Disabled -EA 0
}

# Block dangerous ports (TCP and UDP separately)
135,139,445,1900,5357 | ForEach-Object {
    New-NetFirewallRule -DisplayName "Block-$_-TCP" -Direction Inbound -Protocol TCP -LocalPort $_ -Action Block
    New-NetFirewallRule -DisplayName "Block-$_-UDP" -Direction Inbound -Protocol UDP -LocalPort $_ -Action Block
}

# Disable SMB
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Force -EA 0
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -EA 0
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -NoRestart -EA 0
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -NoRestart -EA 0

Write-Host "Hardening complete - Only Tailscale + RDP allowed" -ForegroundColor Green