# Windows Firewall Security Verification - Language Independent
# Works on all Windows language versions

Write-Host "=== FIREWALL SECURITY VERIFICATION ===" -ForegroundColor Green
Write-Host "Date: $(Get-Date)" -ForegroundColor Gray
Write-Host ""

# 1. ACTIVE FIREWALL RULES ANALYSIS (by technical criteria)
Write-Host "1. FIREWALL RULES ANALYSIS" -ForegroundColor Yellow

$inboundAllow = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Allow -EA 0
$outboundAllow = Get-NetFirewallRule -Direction Outbound -Enabled True -Action Allow -EA 0
$inboundBlock = Get-NetFirewallRule -Direction Inbound -Enabled True -Action Block -EA 0

# Categorize rules by function, not name
$systemRules = @()
$tailscaleRules = @()
$rdpRules = @()
$otherRules = @()

foreach ($rule in $inboundAllow) {
    $portFilter = $rule | Get-NetFirewallPortFilter -EA 0
    $addressFilter = $rule | Get-NetFirewallAddressFilter -EA 0
    $appFilter = $rule | Get-NetFirewallApplicationFilter -EA 0
    
    # System/Loopback rules (highest priority)
    $interfaceFilter = $rule | Get-NetFirewallInterfaceTypeFilter -EA 0
    if ($interfaceFilter.InterfaceType -eq "Loopback" -or $rule.DisplayName -match "Loop|DHCP|DNS") {
        $systemRules += $rule
    }
    # RDP rules (port 3389) - check BEFORE Tailscale to avoid double-categorization
    elseif ($portFilter -and ($portFilter.LocalPort -eq 3389 -or $portFilter.LocalPort -eq "3389")) {
        $rdpRules += $rule
    }
    # Tailscale rules (100.64.0.0/10 or tailscale process) - but NOT RDP
    elseif ((($addressFilter -and ($addressFilter.RemoteAddress -match "100\.64\." -or $addressFilter.RemoteAddress -eq "100.64.0.0/10" -or $addressFilter.RemoteAddress -match "100\.64\.0\.0/")) -or 
            ($appFilter -and $appFilter.Program -match "tailscale")) -and
            !($portFilter -and ($portFilter.LocalPort -eq 3389 -or $portFilter.LocalPort -eq "3389"))) {
        $tailscaleRules += $rule
    }
    else {
        $otherRules += $rule
    }
}

Write-Host "System Rules (Loopback/DNS/DHCP): $($systemRules.Count)" -ForegroundColor Green
Write-Host "Tailscale Rules: $($tailscaleRules.Count)" -ForegroundColor Green
Write-Host "RDP Rules: $($rdpRules.Count)" -ForegroundColor $(if($rdpRules.Count -eq 1){'Green'}else{'Yellow'})
Write-Host "Other Allow Rules: $($otherRules.Count)" -ForegroundColor $(if($otherRules.Count -le 3){'Green'}else{'Red'})
Write-Host "Block Rules: $($inboundBlock.Count)" -ForegroundColor $(if($inboundBlock -and $inboundBlock.Count -ge 5){'Green'}else{'Yellow'})

if ($otherRules.Count -gt 3) {
    Write-Host "Other rules:" -ForegroundColor Yellow
    $otherRules | Select DisplayName,@{N='Port';E={($_ | Get-NetFirewallPortFilter -EA 0).LocalPort}} | ft -AutoSize
}
Write-Host ""

# 2. CRITICAL PORTS ANALYSIS
Write-Host "2. CRITICAL PORTS ANALYSIS" -ForegroundColor Yellow

$dangerousPorts = @(445,139,135,1900,5357,3389)
$listeningPorts = Get-NetTCPConnection -State Listen | Where-Object {$_.LocalPort -in $dangerousPorts}

Write-Host "Critical ports listening:" -ForegroundColor Cyan
$portDetails = $listeningPorts | Select-Object LocalAddress,LocalPort,@{N='Process';E={(Get-Process -Id $_.OwningProcess -EA 0).Name}} | Sort-Object LocalPort
$portDetails | ft -AutoSize

# Analyze each port
$portAnalysis = @{}
foreach ($port in $dangerousPorts) {
    $connections = $listeningPorts | Where-Object {$_.LocalPort -eq $port}
    $localOnly = ($connections | Where-Object {$_.LocalAddress -eq "127.0.0.1" -or $_.LocalAddress -eq "::1"}).Count
    $allInterfaces = ($connections | Where-Object {$_.LocalAddress -eq "0.0.0.0" -or $_.LocalAddress -eq "::"}).Count
    $tailscaleInterface = ($connections | Where-Object {$_.LocalAddress -match "^100\."}).Count
    
    $portAnalysis[$port] = @{
        Total = $connections.Count
        LocalOnly = $localOnly
        AllInterfaces = $allInterfaces
        TailscaleInterface = $tailscaleInterface
    }
}

Write-Host "Port Security Analysis:" -ForegroundColor Cyan
foreach ($port in $dangerousPorts) {
    $analysis = $portAnalysis[$port]
    $status = if ($analysis.Total -eq 0) { "CLOSED" }
              elseif ($analysis.AllInterfaces -gt 0) { "DANGEROUS (0.0.0.0)" }
              elseif ($analysis.TailscaleInterface -gt 0) { "TAILSCALE ONLY" }
              elseif ($analysis.LocalOnly -gt 0) { "LOCAL ONLY" }
              else { "UNKNOWN" }
    
    $color = switch ($status) {
        "CLOSED" { "Green" }
        "LOCAL ONLY" { "Green" }
        "TAILSCALE ONLY" { if($port -eq 3389) {"Green"} else {"Yellow"} }
        "DANGEROUS (0.0.0.0)" { "Red" }
        default { "Yellow" }
    }
    
    $portName = switch ($port) {
        445 { "SMB" }
        139 { "NetBIOS" }
        135 { "RPC" }
        1900 { "SSDP" }
        5357 { "WSD" }
        3389 { "RDP" }
        default { "Port $port" }
    }
    
    Write-Host "$portName ($port): $status ($($analysis.Total) listeners)" -ForegroundColor $color
}
Write-Host ""

# 3. TAILSCALE STATUS (IP-based detection)
Write-Host "3. TAILSCALE STATUS" -ForegroundColor Yellow

$tailscaleIPs = Get-NetIPAddress | Where-Object {$_.IPAddress -match "^100\.(6[4-9]|[7-9]\d|1[0-2]\d)" -and $_.AddressFamily -eq "IPv4"}
if ($tailscaleIPs) {
    Write-Host "Tailscale interfaces found:" -ForegroundColor Green
    $tailscaleIPs | Select IPAddress,InterfaceAlias,InterfaceIndex | ft -AutoSize
    
    # Check RDP rule for Tailscale network
    $rdpTailscaleRule = $rdpRules | Where-Object {
        $addrFilter = $_ | Get-NetFirewallAddressFilter -EA 0
        $addrFilter -and ($addrFilter.RemoteAddress -match "100\.64\." -or $addrFilter.RemoteAddress -eq "100.64.0.0/10" -or $addrFilter.RemoteAddress -match "100\.64\.0\.0/")
    }
    Write-Host "RDP-Tailscale Rule: $(if($rdpTailscaleRule){'✓ CONFIGURED'}else{'✗ MISSING'})" -ForegroundColor $(if($rdpTailscaleRule){'Green'}else{'Red'})
} else {
    Write-Host "✗ NO TAILSCALE INTERFACES FOUND!" -ForegroundColor Red
}
Write-Host ""

# 4. SERVICES STATUS (by service name - language independent)
Write-Host "4. CRITICAL SERVICES STATUS" -ForegroundColor Yellow

$criticalServices = @(
    @{Name="LanmanServer"; Desc="File/Print Sharing"},
    @{Name="SSDPSRV"; Desc="SSDP Discovery"},
    @{Name="upnphost"; Desc="UPnP Device Host"},
    @{Name="WMPNetworkSvc"; Desc="Media Player Network"},
    @{Name="XboxNetApiSvc"; Desc="Xbox Live Network"},
    @{Name="CDPSvc"; Desc="Connected Devices"},
    @{Name="DsSvc"; Desc="Data Sharing"},
    @{Name="DiagTrack"; Desc="Diagnostics Tracking"},
    @{Name="RemoteRegistry"; Desc="Remote Registry"},
    @{Name="SharedAccess"; Desc="Internet Connection Sharing"}
)

$secureServices = 0
foreach ($svc in $criticalServices) {
    $service = Get-Service -Name $svc.Name -EA 0
    if ($service) {
        $isSecure = ($service.Status -eq "Stopped" -and $service.StartType -eq "Disabled")
        if ($isSecure) { $secureServices++ }
        
        $status = if ($isSecure) { "SECURE" } else { "ACTIVE" }
        $color = if ($isSecure) { "Green" } else { "Red" }
        Write-Host "$($svc.Desc): $status ($($service.Status)/$($service.StartType))" -ForegroundColor $color
    } else {
        Write-Host "$($svc.Desc): Not installed" -ForegroundColor Gray
        $secureServices++  # Count as secure if not installed
    }
}
Write-Host ""

# 5. FIREWALL BLOCK RULES VERIFICATION
Write-Host "5. FIREWALL BLOCK RULES" -ForegroundColor Yellow

$expectedBlocks = @(135,139,445,1900,5357)
$actualBlocks = 0

foreach ($port in $expectedBlocks) {
    $tcpBlock = $null
    $udpBlock = $null
    
    if ($inboundBlock) {
        $tcpBlock = $inboundBlock | Where-Object {
            $portFilter = $_ | Get-NetFirewallPortFilter -EA 0
            $portFilter -and $portFilter.LocalPort -eq $port -and $portFilter.Protocol -eq "TCP"
        }
        $udpBlock = $inboundBlock | Where-Object {
            $portFilter = $_ | Get-NetFirewallPortFilter -EA 0
            $portFilter -and $portFilter.LocalPort -eq $port -and $portFilter.Protocol -eq "UDP"
        }
    }
    
    $blocked = ($tcpBlock -and $tcpBlock.Count -gt 0) -and ($udpBlock -and $udpBlock.Count -gt 0)
    if ($blocked) { $actualBlocks++ }
    
    Write-Host "Port ${port}: $(if($blocked){'✓ BLOCKED (TCP+UDP)'}else{'✗ NOT BLOCKED'})" -ForegroundColor $(if($blocked){'Green'}else{'Red'})
}
Write-Host ""

# 6. SECURITY SCORE CALCULATION
Write-Host "6. SECURITY ASSESSMENT" -ForegroundColor Yellow

$score = 0
$maxScore = 100

# RDP via Tailscale only (25 points)
if ($rdpTailscaleRule -and $portAnalysis[3389].AllInterfaces -eq 0) { $score += 25 }

# No dangerous ports on all interfaces (25 points)
$dangerousOpen = ($portAnalysis[445].AllInterfaces + $portAnalysis[139].AllInterfaces + $portAnalysis[135].AllInterfaces + $portAnalysis[1900].AllInterfaces + $portAnalysis[5357].AllInterfaces)
if ($dangerousOpen -eq 0) { $score += 25 }

# Tailscale active (15 points)
if ($tailscaleIPs) { $score += 15 }

# Services secured (15 points)
$serviceScore = [math]::Round(($secureServices / $criticalServices.Count) * 15)
$score += $serviceScore

# Block rules active (10 points)
$blockScore = [math]::Round(($actualBlocks / $expectedBlocks.Count) * 10)
$score += $blockScore

# Few other rules (10 points)
if ($otherRules.Count -le 3) { $score += 10 }

# Determine security level
$securityLevel = if ($score -ge 85) { "SECURE" }
                elseif ($score -ge 70) { "GOOD" }
                elseif ($score -ge 50) { "ACCEPTABLE" }
                else { "INSECURE" }

$scoreColor = if ($score -ge 85) { "Green" }
             elseif ($score -ge 70) { "Yellow" }
             else { "Red" }

Write-Host "SECURITY SCORE: $score/$maxScore - $securityLevel" -ForegroundColor $scoreColor

# Recommendations
if ($score -lt 85) {
    Write-Host "`nRECOMMENDATIONS:" -ForegroundColor Yellow
    if (!$rdpTailscaleRule) { Write-Host "- Configure RDP for Tailscale network only" -ForegroundColor Red }
    if ($dangerousOpen -gt 0) { Write-Host "- Block dangerous ports from external access" -ForegroundColor Red }
    if (!$tailscaleIPs) { Write-Host "- Install and configure Tailscale" -ForegroundColor Red }
    if ($secureServices -lt $criticalServices.Count) { Write-Host "- Disable more unnecessary services" -ForegroundColor Yellow }
    if ($actualBlocks -lt $expectedBlocks.Count) { Write-Host "- Add missing firewall block rules" -ForegroundColor Yellow }
    if ($otherRules.Count -gt 3) { Write-Host "- Review and remove unnecessary firewall rules" -ForegroundColor Yellow }
}

Write-Host "`n=== VERIFICATION COMPLETED ===" -ForegroundColor Green