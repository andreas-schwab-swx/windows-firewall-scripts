# Windows Firewall Security Configuration Verification (Language-Independent)
# Run after restart

Write-Host "Windows Firewall Security Configuration - Verification (Intl)" -ForegroundColor Green
Write-Host "Date: $(Get-Date)" -ForegroundColor Gray
Write-Host ""

# 1. CHECK ACTIVE FIREWALL RULES (by technical criteria)
Write-Host "1. ACTIVE FIREWALL RULES" -ForegroundColor Yellow
Write-Host "Expected inbound rules (by port/address):" -ForegroundColor Cyan

$inboundRules = Get-NetFirewallRule -Direction Inbound -Enabled True

# RDP via Tailscale only (TCP 3389, RemoteAddress 100.64.0.0/10)
$rdpTailscale = $inboundRules | Where-Object {
    $_.Action -eq "Allow" -and
    $_.Direction -eq "Inbound" -and
    $_.Enabled -eq "True" -and
    $_.LocalPort -eq 3389 -and
    ($_.RemoteAddress -like "100.*" -or $_.RemoteAddress -eq "100.64.0.0/10")
}
# Block RDP from other sources
$rdpBlock = $inboundRules | Where-Object {
    $_.Action -eq "Block" -and
    $_.Direction -eq "Inbound" -and
    $_.Enabled -eq "True" -and
    $_.LocalPort -eq 3389
}
# Allow Tailscale process (if present)
$tailscalePath = "C:\\Program Files\\Tailscale\\tailscaled.exe"
$tailscaleProcRule = $inboundRules | Where-Object {
    $_.Action -eq "Allow" -and $_.Program -eq $tailscalePath
}

Write-Host "RDP via Tailscale: $($rdpTailscale.Count) rule(s)" -ForegroundColor Green
Write-Host "Block RDP (other): $($rdpBlock.Count) rule(s)" -ForegroundColor Green
Write-Host "Tailscale process allowed: $($tailscaleProcRule.Count) rule(s)" -ForegroundColor Green

# Other allowed inbound rules
$otherAllow = $inboundRules | Where-Object {
    $_.Action -eq "Allow" -and
    ($_.LocalPort -ne 3389 -or $_.LocalPort -eq $null) -and
    ($_.Program -ne $tailscalePath -or !$_.Program)
}
Write-Host "Other allowed inbound rules: $($otherAllow.Count)" -ForegroundColor $(if($otherAllow.Count -le 5) {"Yellow"} else {"Red"})
if ($otherAllow.Count -gt 0) {
    $otherAllow | Select-Object DisplayName, LocalPort, Program | Format-Table -AutoSize
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
$tailscaleIPs = Get-NetIPAddress | Where-Object {$_.InterfaceAlias -like "*Tailscale*"}
if ($tailscaleIPs) {
    Write-Host "Tailscale interfaces found:" -ForegroundColor Green
    $tailscaleIPs | Format-Table -AutoSize
} else {
    Write-Host "ERROR: No Tailscale interfaces found!" -ForegroundColor Red
}
Write-Host ""

# 4. WINDOWS SERVICES STATUS (by ServiceName)
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

# 5. SECURITY ASSESSMENT (same logic, language-independent)
Write-Host "5. SECURITY ASSESSMENT" -ForegroundColor Yellow
$score = 0
if ($smbPorts.Count -eq 0) { $score += 30 }
if ($netbiosPorts.Count -le 1) { $score += 20 }
if ($rdpTailscale.Count -ge 1) { $score += 20 }
$stoppedServices = 0
foreach ($svc in $services) {
    $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
    if ($service -and $service.Status -eq "Stopped") { $stoppedServices++ }
}
$score += [math]::Round(($stoppedServices / $services.Count) * 15)
if ($otherAllow.Count -le 5) { $score += 15 }
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
