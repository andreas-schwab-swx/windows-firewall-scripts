# Windows Original Configuration Restore Script
# Simple restore to Windows defaults
# Run as Administrator!

# 1. RESET FIREWALL TO DEFAULTS
Write-Host "Resetting Windows Firewall to defaults..." -ForegroundColor Cyan
netsh advfirewall reset

# 2. RESTORE SERVICES TO DEFAULT STARTUP TYPES
Write-Host "Restoring services to default..." -ForegroundColor Cyan

# Set services back to Windows default startup types
Set-Service -Name "LanmanServer" -StartupType Manual
Set-Service -Name "WMPNetworkSvc" -StartupType Manual
Set-Service -Name "XboxNetApiSvc" -StartupType Manual
Set-Service -Name "DsSvc" -StartupType Manual
Set-Service -Name "CDPSvc" -StartupType Automatic
Set-Service -Name "SSDPSRV" -StartupType Manual
Set-Service -Name "upnphost" -StartupType Manual

# Start key services
Start-Service -Name "LanmanServer"
Start-Service -Name "CDPSvc"

# 3. RESTORE NETBIOS TO DEFAULT
Write-Host "Restoring NetBIOS to default..." -ForegroundColor Cyan
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true}
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(0)  # 0 = Default (use DHCP setting)
}

Write-Host "Windows default configuration restored." -ForegroundColor Green
Write-Host "Press any key to restart the computer..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Restart-Computer -Force