# Windows Firewall Security Configuration (Language-Independent)
# Run all commands as Administrator!

# 0. REMOVE ALL EXISTING INBOUND RULES
Get-NetFirewallRule -Direction Inbound | Remove-NetFirewallRule

# 1. SET ONLY DESIRED INBOUND RULES
# Allow RDP via Tailscale only
New-NetFirewallRule -DisplayName "RDP via Tailscale Only" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress "100.64.0.0/10" -Action Allow -Profile Any
# Block RDP from all other sources
New-NetFirewallRule -DisplayName "Block RDP Internet Only" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block -Profile Any
# Allow Tailscale process (if present)
$tailscalePath = "C:\\Program Files\\Tailscale\\tailscaled.exe"
if (Test-Path $tailscalePath) {
    New-NetFirewallRule -DisplayName "Tailscale-Process" -Direction Inbound -Program $tailscalePath -Action Allow
}

# 2. DEFAULT: BLOCK ALL INBOUND, ALLOW ALL OUTBOUND
Set-NetFirewallProfile -Profile Domain,Public,Private -DefaultInboundAction Block -DefaultOutboundAction Allow

# 3. DISABLE DANGEROUS WINDOWS SERVICES (by ServiceName, not DisplayName)
$dangerousServices = @(
    'LanmanServer',   # Server (SMB)
    'WMPNetworkSvc',  # Windows Media Player Network Sharing
    'XboxNetApiSvc',  # Xbox Live Networking
    'DsSvc',          # Data Sharing Service
    'CDPSvc'          # Connected Devices Platform Service
)
foreach ($svc in $dangerousServices) {
    if (Get-Service -Name $svc -ErrorAction SilentlyContinue) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service -Name $svc -StartupType Disabled
    }
}

# 4. DISABLE SMB AND NETBIOS VIA REGISTRY
Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "SMB1" -Value 0 -Force
Set-ItemProperty -Path "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters" -Name "SMB2" -Value 0 -Force

$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true}
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2) | Out-Null
}

Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -NoRestart

# 5. DISABLE WSD/SSDP SERVICES (by ServiceName)
$wsdServices = @('SSDPSRV', 'upnphost', 'WSDSvc', 'WSDPrintDevice')
foreach ($svc in $wsdServices) {
    $regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Services\\$svc"
    if (Test-Path $regPath) {
        Set-ItemProperty -Path $regPath -Name "Start" -Value 4 -Force
    }
}
# Block WSD/SSDP ports
New-NetFirewallRule -DisplayName "Block WSD/SSDP" -Direction Inbound -Protocol UDP -LocalPort 5357 -Action Block

Write-Host "Firewall hardened for Tailscale-only RDP. All other inbound connections blocked." -ForegroundColor Green
