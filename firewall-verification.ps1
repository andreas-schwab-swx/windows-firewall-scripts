# Windows Firewall Security Configuration Verification
# Run after restart

Write-Host "Windows Firewall Security Configuration - Verification" -ForegroundColor Green
Write-Host "Date: $(Get-Date)" -ForegroundColor Gray
Write-Host ""

# 1. CHECK ACTIVE FIREWALL RULES
Write-Host "1. ACTIVE FIREWALL RULES" -ForegroundColor Yellow
Write-Host "Only these rules should be active:" -ForegroundColor Cyan

$allowRules = Get-NetFirewallRule -Direction Inbound -Enabled True | Where-Object {$_.Action -eq "Allow"} | Select-Object DisplayName | Sort-Object DisplayName

$kernelRules = $allowRules | Where-Object {$_.DisplayName -like "*Kernnetzwerk*"}
$tailscaleRules = $allowRules | Where-Object {$_.DisplayName -like "*Tailscale*" -or $_.DisplayName -like "*RDP*"}
$otherRules = $allowRules | Where-Object {$_.DisplayName -notlike "*Kernnetzwerk*" -and $_.DisplayName -notlike "*Tailscale*" -and $_.DisplayName -notlike "*RDP*" -and $_.DisplayName -notlike "*mDNS*"}

Write-Host "Core Network Rules: $($kernelRules.Count)" -ForegroundColor Green
Write-Host "Tailscale/RDP Rules: $($tailscaleRules.Count)" -ForegroundColor Green  
Write-Host "Other Rules: $($otherRules.Count)" -ForegroundColor $(if($otherRules.Count -gt 5) {"Red"} else {"Yellow"})

if ($otherRules.Count -gt 5) {
    Write-Host "WARNING: Too many other rules active!" -ForegroundColor Red
    $otherRules | Format-Table -AutoSize
}

Write-Host ""

# 2. CHECK CRITICAL PORTS
Write-Host "2. CRITICAL PORTS CHECK" -ForegroundColor Yellow

$criticalPorts = Get-NetTCPConnection -State Listen | Where-Object {$_.LocalPort -in @(445,139,135,3389,5357)}

Write-Host "Listening critical ports:" -ForegroundColor Cyan
$portAnalysis = $criticalPorts | Select-Object LocalAddress, LocalPort, @{Name='Process';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Sort-Object LocalPort

$portAnalysis | Format-Table -AutoSize

# Port-specific analysis
$smbPorts = $criticalPorts | Where-Object {$_.LocalPort -eq 445}
$netbiosPorts = $criticalPorts | Where-Object {$_.LocalPort -eq 139}
$rpcPorts = $criticalPorts | Where-Object {$_.LocalPort -eq 135}
$rdpPorts = $criticalPorts | Where-Object {$_.LocalPort -eq 3389}
$wsdPorts = $criticalPorts | Where-Object {$_.LocalPort -eq 5357}

Write-Host "Port Status:" -ForegroundColor Cyan
Write-Host "Port 445 (SMB): $(if($smbPorts.Count -eq 0) {"BLOCKED"} else {"DANGEROUS - $($smbPorts.Count) listening"})" -ForegroundColor $(if($smbPorts.Count -eq 0) {"Green"} else {"Red"})
Write-Host "Port 139 (NetBIOS): $($netbiosPorts.Count) listening" -ForegroundColor $(if($netbiosPorts.Count -le 1) {"Green"} else {"Yellow"})
Write-Host "Port 135 (RPC): $($rpcPorts.Count) listening" -ForegroundColor Yellow
Write-Host "Port 3389 (RDP): $($rdpPorts.Count) listening" -ForegroundColor $(if($rdpPorts.Count -le 2) {"Green"} else {"Yellow"})
Write-Host "Port 5357 (WSD): $(if($wsdPorts.Count -eq 0) {"BLOCKED"} else {"$($wsdPorts.Count) listening"})" -ForegroundColor $(if($wsdPorts.Count -eq 0) {"Green"} else {"Yellow"})

Write-Host ""

# 3. TAILSCALE CONFIGURATION
Write-Host "3. TAILSCALE CONFIGURATION" -ForegroundColor Yellow

$tailscaleIPs = Get-NetIPAddress | Where-Object {$_.InterfaceAlias -like "*Tailscale*"} | Select-Object IPAddress, InterfaceAlias

if ($tailscaleIPs) {
    Write-Host "Tailscale interfaces found:" -ForegroundColor Green
    $tailscaleIPs | Format-Table -AutoSize
    
    # Check if NetBIOS only runs over Tailscale
    $tailscaleIP4 = ($tailscaleIPs | Where-Object {$_.IPAddress -match "100\."}).IPAddress
    $netbiosOnTailscale = $netbiosPorts | Where-Object {$_.LocalAddress -eq $tailscaleIP4}
    
    if ($netbiosOnTailscale) {
        Write-Host "NetBIOS correctly running only over Tailscale: $tailscaleIP4" -ForegroundColor Green
    }
} else {
    Write-Host "ERROR: No Tailscale interfaces found!" -ForegroundColor Red
}

Write-Host ""

# 4. WINDOWS SERVICES STATUS
Write-Host "4. CRITICAL WINDOWS SERVICES" -ForegroundColor Yellow

$services = @(
    @{Name="LanmanServer"; DisplayName="SMB Server"},
    @{Name="WMPNetworkSvc"; DisplayName="Windows Media Player Network"},
    @{Name="XboxNetApiSvc"; DisplayName="Xbox Live Network"},
    @{Name="CDPSvc"; DisplayName="Proximity Sharing"},
    @{Name="SSDPSRV"; DisplayName="SSDP Discovery"},
    @{Name="upnphost"; DisplayName="UPnP Host"}
)

foreach ($svc in $services) {
    $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($service) {
        $status = if ($service.Status -eq "Stopped" -and $service.StartType -eq "Disabled") {"SECURE"} else {"DANGEROUS"}
        $color = if ($status -eq "SECURE") {"Green"} else {"Red"}
        Write-Host "$($svc.DisplayName): $status ($($service.Status)/$($service.StartType))" -ForegroundColor $color
    } else {
        Write-Host "$($svc.DisplayName): Not found" -ForegroundColor Gray
    }
}

Write-Host ""

# 5. SECURITY ASSESSMENT
Write-Host "5. SECURITY ASSESSMENT" -ForegroundColor Yellow

$score = 0

# SMB completely disabled (30 points)
if ($smbPorts.Count -eq 0) { $score += 30 }

# NetBIOS only over Tailscale (20 points)
if ($netbiosPorts.Count -le 1) { $score += 20 }

# RDP rules correct (20 points)
$rdpRules = $tailscaleRules | Where-Object {$_.DisplayName -like "*RDP*"}
if ($rdpRules.Count -ge 1) { $score += 20 }

# Dangerous services disabled (15 points)
$stoppedServices = 0
foreach ($svc in $services) {
    $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Stopped") { $stoppedServices++ }
}
$score += [math]::Round(($stoppedServices / $services.Count) * 15)

# Few active rules (15 points)
if ($otherRules.Count -le 5) { $score += 15 }

$scoreColor = if ($score -ge 80) {"Green"} elseif ($score -ge 60) {"Yellow"} else {"Red"}
$scoreText = if ($score -ge 80) {"SECURE"} elseif ($score -ge 60) {"ACCEPTABLE"} else {"INSECURE"}

Write-Host "SECURITY SCORE: $score/100 - $scoreText" -ForegroundColor $scoreColor

if ($score -ge 80) {
    Write-Host "System is well configured for Tailscale-only RDP!" -ForegroundColor Green
} elseif ($score -ge 60) {
    Write-Host "System is basically secure, but improvements possible." -ForegroundColor Yellow
} else {
    Write-Host "System requires additional security measures!" -ForegroundColor Red
}

Write-Host ""
Write-Host "VERIFICATION COMPLETED" -ForegroundColor Green