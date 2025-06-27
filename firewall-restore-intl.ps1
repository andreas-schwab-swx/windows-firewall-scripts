# Windows Firewall Security Configuration Restore (Language-Independent)
# Run all commands as Administrator!

# 1. REMOVE ALL CUSTOM INBOUND RULES CREATED BY firewall-configuration-intl.ps1
$customRules = @(
    "RDP via Tailscale Only",
    "Block RDP Internet Only",
    "Tailscale-Process",
    "Block WSD/SSDP"
)
foreach ($rule in $customRules) {
    Get-NetFirewallRule -DisplayName $rule -ErrorAction SilentlyContinue | Remove-NetFirewallRule
}

# 2. RESTORE DEFAULT FIREWALL PROFILES
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction NotConfigured -DefaultOutboundAction NotConfigured

# 3. ENABLE PREVIOUSLY DISABLED SERVICES (if present)
$restoreServices = @(
    'LanmanServer',
    'WMPNetworkSvc',
    'XboxNetApiSvc',
    'DsSvc',
    'CDPSvc',
    'SSDPSRV',
    'upnphost',
    'WSDSvc',
    'WSDPrintDevice'
)
foreach ($svc in $restoreServices) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        Set-Service -Name $svc -StartupType Automatic -ErrorAction SilentlyContinue
        Start-Service -Name $svc -ErrorAction SilentlyContinue
    }
}

# 4. RESTORE SMB AND NETBIOS (if needed)
Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "SMB1" -Value 1 -Force
Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "SMB2" -Value 1 -Force

$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true}
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(0) | Out-Null
}

Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -NoRestart
Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -NoRestart

Write-Host "Firewall and services restored to default or previous state. Please review and adjust as needed." -ForegroundColor Yellow
