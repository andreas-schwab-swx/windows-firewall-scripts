# Windows Firewall Security Configuration for Tailscale-only RDP
# Run all commands as Administrator!

# 1. DISABLE DANGEROUS FIREWALL RULES
Disable-NetFirewallRule -DisplayGroup "Netzwerkerkennung"
Disable-NetFirewallRule -DisplayGroup "Datei- und Druckerfreigabe"
Disable-NetFirewallRule -DisplayGroup "Remoteunterstützung"
Disable-NetFirewallRule -DisplayName "*Wiedergabe auf Gerät*"
Disable-NetFirewallRule -DisplayName "*Wi-Fi Direct*"
Disable-NetFirewallRule -DisplayName "*WFD*"
Disable-NetFirewallRule -DisplayName "*drahtlos*"
Disable-NetFirewallRule -DisplayName "*AllJoyn*"
Disable-NetFirewallRule -DisplayName "*DIAL*"
Disable-NetFirewallRule -DisplayName "*verbundene Geräte*"
Disable-NetFirewallRule -DisplayName "*Übermittlungsoptimierung*"

# 2. CONFIGURE RDP FOR TAILSCALE ONLY
New-NetFirewallRule -DisplayName "RDP via Tailscale Only" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress "100.64.0.0/10" -Action Allow
New-NetFirewallRule -DisplayName "Block RDP Internet Only" -Direction Inbound -Protocol TCP -LocalPort 3389 -InterfaceType RemoteAccess -Action Block
New-NetFirewallRule -DisplayName "Tailscale-Process" -Direction Inbound -Program "C:\Program Files\Tailscale\tailscaled.exe" -Action Allow

# 3. DISABLE DANGEROUS WINDOWS SERVICES
Stop-Service -Name "LanmanServer" -Force
Set-Service -Name "LanmanServer" -StartupType Disabled
Stop-Service -Name "WMPNetworkSvc" -Force
Set-Service -Name "WMPNetworkSvc" -StartupType Disabled
Stop-Service -Name "XboxNetApiSvc" -Force
Set-Service -Name "XboxNetApiSvc" -StartupType Disabled
Set-Service -Name "DsSvc" -StartupType Disabled
Stop-Service -Name "CDPSvc" -Force
Set-Service -Name "CDPSvc" -StartupType Disabled

# 4. DISABLE SMB AND NETBIOS VIA REGISTRY
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB2" -Value 0 -Force

$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true}
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)
}

Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -NoRestart

# 5. DISABLE WSD/SSDP SERVICES
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV") {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV" -Name "Start" -Value 4 -Force
}
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost") {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost" -Name "Start" -Value 4 -Force
}
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSDSvc") {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSDSvc" -Name "Start" -Value 4 -Force
}
if (Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSDPrintDevice") {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\WSDPrintDevice" -Name "Start" -Value 4 -Force
}
New-NetFirewallRule -DisplayName "Block WSD/SSDP" -Direction Inbound -Protocol UDP -LocalPort 5357 -Action Block

Write-Host "Configuration completed." -ForegroundColor Green
Write-Host "Press any key to restart the computer..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Restart-Computer -Force