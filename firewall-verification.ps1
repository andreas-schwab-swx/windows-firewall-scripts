# Windows Security Analysis - External Security Focus
# Checks what matters: services, firewall rules, and external accessibility

Write-Host "=== SECURITY ANALYSIS - EXTERNAL FOCUS ===" -ForegroundColor Green
Write-Host "Date: $(Get-Date)" -ForegroundColor Gray
Write-Host ""

$issues = @()
$strengths = @()

# 1. CRITICAL SERVICES STATUS
Write-Host "1. CRITICAL SERVICES STATUS" -ForegroundColor Yellow

$criticalServices = @(
    @{Name="LanmanServer"; Desc="File/Print Sharing"; Critical=$true},
    @{Name="SSDPSRV"; Desc="SSDP Discovery"; Critical=$true},
    @{Name="upnphost"; Desc="UPnP Device Host"; Critical=$true},
    @{Name="WMPNetworkSvc"; Desc="Media Player Network"; Critical=$false},
    @{Name="XboxNetApiSvc"; Desc="Xbox Live Network"; Critical=$false},
    @{Name="CDPSvc"; Desc="Connected Devices"; Critical=$false},
    @{Name="RemoteRegistry"; Desc="Remote Registry"; Critical=$true},
    @{Name="SharedAccess"; Desc="Internet Sharing"; Critical=$false}
)

Write-Host "Service Security Status:" -ForegroundColor Cyan
foreach ($svc in $criticalServices) {
    $service = Get-Service -Name $svc.Name -EA 0
    if ($service) {
        $isSecure = ($service.Status -eq "Stopped" -and $service.StartType -eq "Disabled")
        $color = if ($isSecure) { "Green" } elseif ($svc.Critical) { "Red" } else { "Yellow" }
        $status = if ($isSecure) { "✓ SECURE" } else { "✗ RUNNING" }
        
        Write-Host "  $($svc.Desc): $status ($($service.Status)/$($service.StartType))" -ForegroundColor $color
        
        if ($isSecure) {
            $strengths += "$($svc.Desc) is properly disabled"
        } else {
            if ($svc.Critical) {
                $issues += "Disable critical service: $($svc.Desc)"
            } else {
                $issues += "Consider disabling: $($svc.Desc)"
            }
        }
    } else {
        Write-Host "  $($svc.Desc): ✓ NOT INSTALLED" -ForegroundColor Green
        $strengths += "$($svc.Desc) is not installed"
    }
}

Write-Host ""

# 2. FIREWALL RULES ANALYSIS
Write-Host "2. FIREWALL RULES ANALYSIS" -ForegroundColor Yellow

# Check firewall status
$profiles = Get-NetFirewallProfile
Write-Host "Firewall Profile Status:" -ForegroundColor Cyan
foreach ($profile in $profiles) {
    $status = if ($profile.Enabled -and $profile.DefaultInboundAction -eq "Block") { "✓ SECURE" } else { "✗ INSECURE" }
    $color = if ($profile.Enabled -and $profile.DefaultInboundAction -eq "Block") { "Green" } else { "Red" }
    Write-Host "  $($profile.Name): $status (Enabled: $($profile.Enabled), Default: $($profile.DefaultInboundAction))" -ForegroundColor $color
}

# Active inbound rules
$inboundRules = Get-NetFirewallRule -Direction Inbound -Enabled True
Write-Host "`nActive Inbound Rules: $($inboundRules.Count)" -ForegroundColor Cyan

if ($inboundRules.Count -eq 0) {
    Write-Host "  ⚠ WARNING: No inbound rules - system might be unreachable!" -ForegroundColor Yellow
    $issues += "No active inbound firewall rules found"
} elseif ($inboundRules.Count -le 5) {
    Write-Host "  ✓ GOOD: Minimal rule set" -ForegroundColor Green
    $strengths += "Minimal firewall rule set ($($inboundRules.Count) rules)"
} else {
    Write-Host "  ⚠ REVIEW: Many rules active ($($inboundRules.Count))" -ForegroundColor Yellow
    $issues += "Many firewall rules active - review needed"
}

Write-Host "`nActive Inbound Rules Details:" -ForegroundColor Cyan
foreach ($rule in $inboundRules) {
    $portFilter = $rule | Get-NetFirewallPortFilter -EA 0
    $addressFilter = $rule | Get-NetFirewallAddressFilter -EA 0
    
    $port = if ($portFilter -and $portFilter.LocalPort) { $portFilter.LocalPort } else { "Any" }
    $address = if ($addressFilter -and $addressFilter.RemoteAddress) { $addressFilter.RemoteAddress } else { "Any" }
    
    # Analyze rule security
    $ruleStatus = "✓"
    $ruleColor = "Green"
    
    if ($address -eq "Any" -and $port -ne "Any") {
        $ruleStatus = "⚠"
        $ruleColor = "Yellow"
    }
    
    Write-Host "  $ruleStatus $($rule.DisplayName) | Port: $port | From: $address | Action: $($rule.Action)" -ForegroundColor $ruleColor
}

Write-Host ""

# 3. TAILSCALE CONFIGURATION
Write-Host "3. TAILSCALE CONFIGURATION" -ForegroundColor Yellow

# Check Tailscale installation
$tailscalePaths = @("${env:ProgramFiles}\Tailscale\tailscaled.exe", "${env:ProgramFiles(x86)}\Tailscale\tailscaled.exe")
$tailscalePath = $tailscalePaths | Where-Object {Test-Path $_} | Select-Object -First 1

if ($tailscalePath) {
    Write-Host "✓ Tailscale Installation: Found ($tailscalePath)" -ForegroundColor Green
    $strengths += "Tailscale is installed"
    
    # Check Tailscale network interface
    $tailscaleIPs = Get-NetIPAddress | Where-Object {$_.IPAddress -match "^100\." -and $_.AddressFamily -eq "IPv4"}
    if ($tailscaleIPs) {
        Write-Host "✓ Tailscale Network: Active" -ForegroundColor Green
        $tailscaleIPs | ForEach-Object {
            Write-Host "  Tailscale IP: $($_.IPAddress) on $($_.InterfaceAlias)" -ForegroundColor Gray
        }
        $strengths += "Tailscale network is active"
    } else {
        Write-Host "⚠ Tailscale Network: Not active" -ForegroundColor Yellow
        $issues += "Tailscale network interface not found"
    }
    
    # Check for Tailscale-specific firewall rules
    $tailscaleRules = $inboundRules | Where-Object {
        $addressFilter = $_ | Get-NetFirewallAddressFilter -EA 0
        $addressFilter -and $addressFilter.RemoteAddress -match "100\.64\."
    }
    
    if ($tailscaleRules) {
        Write-Host "✓ Tailscale Firewall Rules: $($tailscaleRules.Count) found" -ForegroundColor Green
        $strengths += "Tailscale-specific firewall rules configured"
    } else {
        Write-Host "⚠ Tailscale Firewall Rules: None found" -ForegroundColor Yellow
        $issues += "No Tailscale-specific firewall rules found"
    }
} else {
    Write-Host "✗ Tailscale Installation: Not found" -ForegroundColor Red
    $issues += "Tailscale is not installed"
}

Write-Host ""

# 4. SMB CONFIGURATION
Write-Host "4. SMB CONFIGURATION" -ForegroundColor Yellow

$smb1Setting = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -EA 0
$smb2Setting = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB2" -EA 0

Write-Host "SMB Protocol Status:" -ForegroundColor Cyan
if ($smb1Setting -and $smb1Setting.SMB1 -eq 0) {
    Write-Host "  ✓ SMB1: Disabled" -ForegroundColor Green
    $strengths += "SMB1 is disabled"
} else {
    Write-Host "  ✗ SMB1: Enabled or not configured" -ForegroundColor Red
    $issues += "SMB1 should be disabled"
}

if ($smb2Setting -and $smb2Setting.SMB2 -eq 0) {
    Write-Host "  ✓ SMB2: Disabled" -ForegroundColor Green
    $strengths += "SMB2 is disabled"
} else {
    Write-Host "  ⚠ SMB2: Enabled or not configured" -ForegroundColor Yellow
    $issues += "Consider disabling SMB2 if not needed"
}

Write-Host ""

# 5. EXTERNAL ACCESSIBILITY NOTICE
Write-Host "5. EXTERNAL ACCESSIBILITY" -ForegroundColor Yellow
Write-Host "External Port Scan Recommendation:" -ForegroundColor Cyan
Write-Host "  Run from external network: nmap -Pn [your-public-ip]" -ForegroundColor Gray
Write-Host "  Expected result: All ports filtered/closed" -ForegroundColor Gray
Write-Host "  ✓ SECURE: 'filtered tcp ports (no-response)'" -ForegroundColor Green
Write-Host "  ✗ DANGER: Any 'open' ports found" -ForegroundColor Red

Write-Host ""

# 6. SECURITY SUMMARY
Write-Host "6. SECURITY SUMMARY" -ForegroundColor Yellow

Write-Host "`nSECURITY STRENGTHS:" -ForegroundColor Green
if ($strengths.Count -eq 0) {
    Write-Host "  No security strengths identified" -ForegroundColor Gray
} else {
    for ($i = 0; $i -lt $strengths.Count; $i++) {
        Write-Host "  ✓ $($strengths[$i])" -ForegroundColor Green
    }
}

Write-Host "`nSECURITY ISSUES:" -ForegroundColor Red
if ($issues.Count -eq 0) {
    Write-Host "  ✓ No security issues found - excellent!" -ForegroundColor Green
} else {
    for ($i = 0; $i -lt $issues.Count; $i++) {
        Write-Host "  ✗ $($issues[$i])" -ForegroundColor Red
    }
}

# Calculate security score
$totalChecks = $issues.Count + $strengths.Count
$securityScore = if ($totalChecks -gt 0) { [math]::Round(($strengths.Count / $totalChecks) * 100) } else { 0 }
$scoreColor = if ($securityScore -ge 90) { "Green" } elseif ($securityScore -ge 70) { "Yellow" } else { "Red" }

Write-Host "`nSECURITY SCORE: $securityScore% ($($strengths.Count)/$totalChecks checks passed)" -ForegroundColor $scoreColor

$status = if ($securityScore -ge 90) { "EXCELLENT" } elseif ($securityScore -ge 70) { "GOOD" } else { "NEEDS IMPROVEMENT" }
Write-Host "OVERALL STATUS: $status" -ForegroundColor $scoreColor

Write-Host "`n=== ANALYSIS COMPLETED ===" -ForegroundColor Green