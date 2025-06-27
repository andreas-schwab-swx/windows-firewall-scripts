# Windows Firewall Security Configuration for Tailscale-only RDP
# Language Independent - Works on all Windows versions
# Run as Administrator!

Write-Host "Starting Windows Security Hardening..." -ForegroundColor Green

# 1. DISABLE DANGEROUS FIREWALL RULES (by technical criteria, not display names)
Write-Host "Disabling dangerous firewall rules..." -ForegroundColor Yellow

# Get all inbound allow rules and disable dangerous ones by port/protocol
$dangerousRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Where-Object {
    $portFilter = $_ | Get-NetFirewallPortFilter -EA 0
    $appFilter = $_ | Get-NetFirewallApplicationFilter -EA 0
    
    # Network Discovery, File Sharing, Remote Assistance rules
    ($portFilter -and ($portFilter.LocalPort -in @("137","138","139","445","5357","5358","1900","2869","3702") -or 
                       $portFilter.LocalPort -like "*137*" -or $portFilter.LocalPort -like "*139*" -or 
                       $portFilter.LocalPort -like "*445*" -or $portFilter.LocalPort -like "*5357*")) -or
    
    # Applications that should be disabled
    ($appFilter -and ($appFilter.Program -match "svchost\.exe|system" -and 
                     ($_.DisplayName -match "Network Discovery|File.*Print|Remote.*Assist|Cast.*Device|Wi-Fi.*Direct|WFD|AllJoyn|DIAL|Connect.*Device|Delivery.*Optim|Wireless.*Display" -or
                      $_.Group -match "Network Discovery|File.*Print|Remote.*Assist|@.*NetworkDiscovery|@.*FileAndPrint|@.*RemoteAssistance")))
}

# Disable rules but keep essential ones
foreach ($rule in $dangerousRules) {
    # Don't disable essential system rules
    if ($rule.DisplayName -notmatch "Core Networking|Loopback|DHCP|DNS" -and 
        $rule.Group -notmatch "@firewallapi.dll.*CoreNet") {
        Disable-NetFirewallRule -Name $rule.Name -EA 0
    }
}

# Also disable by common English/International group names
@("Network Discovery", "@FirewallAPI.dll,-32752", "@FirewallAPI.dll,-28502", "File and Printer Sharing", 
  "@FirewallAPI.dll,-28502", "Remote Assistance", "@FirewallAPI.dll,-33002") | ForEach-Object {
    Disable-NetFirewallRule -Group $_ -EA 0
}

# Disable specific protocol rules that are commonly dangerous
Get-NetFirewallRule -Direction Inbound -Action Allow | Where-Object {
    $portFilter = $_ | Get-NetFirewallPortFilter -EA 0
    $portFilter -and ($portFilter.Protocol -eq "UDP" -and $portFilter.LocalPort -in @("137","138","1900","5357","5358"))
} | Disable-NetFirewallRule -EA 0

# 2. CONFIGURE RDP FOR TAILSCALE ONLY
Write-Host "Configuring RDP for Tailscale only..." -ForegroundColor Yellow

# First, disable ALL existing RDP rules
Get-NetFirewallRule | Where-Object {
    $portFilter = $_ | Get-NetFirewallPortFilter -EA 0
    $portFilter -and ($portFilter.LocalPort -eq 3389 -or $portFilter.LocalPort -eq "3389")
} | Disable-NetFirewallRule -EA 0

# Create new Tailscale-only RDP rules
New-NetFirewallRule -DisplayName "RDP-Tailscale-Only" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress "100.64.0.0/10" -Action Allow -EA 0

# Block RDP from all other sources (including 0.0.0.0)
New-NetFirewallRule -DisplayName "RDP-Block-All-Others" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Block -EA 0

# Allow Tailscale process
$tailscalePaths = @("${env:ProgramFiles}\Tailscale\tailscaled.exe", "${env:ProgramFiles(x86)}\Tailscale\tailscaled.exe")
$tailscalePath = $tailscalePaths | Where-Object {Test-Path $_} | Select-Object -First 1
if ($tailscalePath) {
    New-NetFirewallRule -DisplayName "Tailscale-Process" -Direction Inbound -Program $tailscalePath -Action Allow -EA 0
    New-NetFirewallRule -DisplayName "Tailscale-Process-Out" -Direction Outbound -Program $tailscalePath -Action Allow -EA 0
}

# Allow Tailscale network range
New-NetFirewallRule -DisplayName "Tailscale-Network" -RemoteAddress "100.64.0.0/10" -Action Allow -EA 0

# 3. DISABLE DANGEROUS WINDOWS SERVICES (by service name - language independent)
Write-Host "Disabling dangerous services..." -ForegroundColor Yellow

$dangerousServices = @(
    "LanmanServer",      # File and Printer Sharing
    "WMPNetworkSvc",     # Windows Media Player Network Sharing  
    "XboxNetApiSvc",     # Xbox Live Networking
    "XblGameSave",       # Xbox Live Game Save
    "XboxGipSvc",        # Xbox Accessory Management
    "DsSvc",             # Data Sharing Service
    "CDPSvc",            # Connected Devices Platform
    "SSDPSRV",           # SSDP Discovery
    "upnphost",          # UPnP Device Host
    "FDResPub",          # Function Discovery Resource Publication
    "fdPHost",           # Function Discovery Provider Host
    "WSearch",           # Windows Search
    "RemoteRegistry",    # Remote Registry
    "SharedAccess",      # Internet Connection Sharing
    "ALG",               # Application Layer Gateway
    "NetTcpPortSharing", # Net.Tcp Port Sharing
    "WinRM",             # Windows Remote Management
    "p2pimsvc",          # Peer Networking Identity Manager
    "p2psvc",            # Peer Networking Grouping
    "PNRPsvc",           # Peer Name Resolution Protocol
    "Spooler",           # Print Spooler (if no printer needed)
    "Fax",               # Fax Service
    "TrkWks",            # Distributed Link Tracking Client
    "SessionEnv",        # Remote Desktop Configuration
    "UmRdpService",      # Remote Desktop Services UserMode Port Redirector
    "DiagTrack",         # Diagnostics Tracking Service
    "dmwappushservice",  # WAP Push Message Routing
    "lfsvc"              # Geolocation Service
)

foreach ($serviceName in $dangerousServices) {
    $service = Get-Service -Name $serviceName -EA 0
    if ($service) {
        Stop-Service -Name $serviceName -Force -EA 0
        Set-Service -Name $serviceName -StartupType Disabled -EA 0
    }
}

# 4. DISABLE SMB AND NETBIOS VIA REGISTRY (language independent)
Write-Host "Disabling SMB and NetBIOS..." -ForegroundColor Yellow

# Disable SMB protocols
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Force -EA 0
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB2" -Value 0 -Force -EA 0

# Disable NetBIOS over TCP/IP on all adapters (except Tailscale)
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {
    $_.IPEnabled -eq $true -and $_.ServiceName -notlike "*Tailscale*" -and $_.Description -notlike "*Tailscale*"
}
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2) | Out-Null  # 2 = Disable NetBIOS over TCP/IP
}

# Disable SMB Windows Features
$smbFeatures = @("SMB1Protocol", "SMB1Protocol-Client", "SMB1Protocol-Server", "WorkFolders-Client")
foreach ($feature in $smbFeatures) {
    Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -EA 0
}

# 5. DISABLE WSD/SSDP SERVICES VIA REGISTRY (language independent)
Write-Host "Disabling WSD/SSDP services..." -ForegroundColor Yellow

$wsdServices = @("SSDPSRV", "upnphost", "WSDSvc", "WSDPrintDevice", "FDResPub", "fdPHost")
foreach ($svc in $wsdServices) {
    $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$svc"
    if (Test-Path $servicePath) {
        Set-ItemProperty -Path $servicePath -Name "Start" -Value 4 -Force -EA 0  # 4 = Disabled
    }
}

# 6. BLOCK DANGEROUS PORTS EXPLICITLY
Write-Host "Adding explicit port blocking rules..." -ForegroundColor Yellow

$dangerousPorts = @(135, 137, 138, 139, 445, 1900, 5357, 5358, 2869, 3702)
foreach ($port in $dangerousPorts) {
    New-NetFirewallRule -DisplayName "Block-${port}-TCP" -Direction Inbound -Protocol TCP -LocalPort $port -Action Block -EA 0
    New-NetFirewallRule -DisplayName "Block-${port}-UDP" -Direction Inbound -Protocol UDP -LocalPort $port -Action Block -EA 0
}

# 7. ESSENTIAL SYSTEM RULES (ensure these are not blocked)
Write-Host "Ensuring essential system connectivity..." -ForegroundColor Yellow

# Loopback interface
New-NetFirewallRule -DisplayName "Loopback-Essential" -Direction Inbound -InterfaceAlias "Loopback*" -Action Allow -EA 0

# DHCP Client
New-NetFirewallRule -DisplayName "DHCP-Client-Essential" -Direction Inbound -Protocol UDP -LocalPort 68 -Action Allow -EA 0

# DNS (outbound)
New-NetFirewallRule -DisplayName "DNS-Out-Essential" -Direction Outbound -Protocol UDP -RemotePort 53 -Action Allow -EA 0

# Windows Update (outbound to Microsoft)
New-NetFirewallRule -DisplayName "WinUpdate-Essential" -Direction Outbound -Protocol TCP -RemotePort 80,443 -Program "${env:windir}\system32\svchost.exe" -Action Allow -EA 0

# 8. SET SECURE FIREWALL DEFAULTS
Write-Host "Setting secure firewall defaults..." -ForegroundColor Yellow

# Enable firewall on all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow

# Disable rule merging for security
Set-NetFirewallProfile -Profile Domain,Public,Private -AllowLocalFirewallRules False -AllowInboundRules False

Write-Host "Configuration completed successfully!" -ForegroundColor Green
Write-Host "System will restart in 10 seconds to apply all changes..." -ForegroundColor Yellow
Write-Host "Press Ctrl+C to cancel restart" -ForegroundColor Red

Start-Sleep -Seconds 10
Restart-Computer -Force