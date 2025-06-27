# Windows Security Analysis - Pre/Post Hardening Check
# Language Independent - Technical Approach
# Run as Administrator to get complete information

Write-Host "=== WINDOWS SECURITY ANALYSIS ===" -ForegroundColor Cyan
Write-Host "Date: $(Get-Date)" -ForegroundColor Gray
Write-Host ""

$issues = @()
$improvements = @()

# 1. DANGEROUS FIREWALL RULES ANALYSIS
Write-Host "1. DANGEROUS FIREWALL RULES ANALYSIS" -ForegroundColor Yellow

# Check dangerous groups by Resource String IDs
$dangerousGroups = @(
    @{ID="@FirewallAPI.dll,-32752"; Name="Network Discovery"; Critical=$true},
    @{ID="@FirewallAPI.dll,-28502"; Name="File and Printer Sharing"; Critical=$true},
    @{ID="@FirewallAPI.dll,-33002"; Name="Remote Assistance"; Critical=$false}
)

Write-Host "Dangerous Rule Groups:" -ForegroundColor Cyan
foreach ($group in $dangerousGroups) {
    $rules = Get-NetFirewallRule -Group $group.ID -Enabled True -Action Allow -EA 0
    $count = if ($rules) { $rules.Count } else { 0 }
    
    if ($count -gt 0) {
        $color = if ($group.Critical) { "Red" } else { "Yellow" }
        Write-Host "  $($group.Name): $count active rules" -ForegroundColor $color
        $issues += "Disable $($group.Name) rules ($count active)"
        
        # Show specific rules
        if ($rules) {
            $rules | Select-Object DisplayName, Direction, Action | Format-Table -AutoSize | Out-String | Write-Host -ForegroundColor Gray
        }
    } else {
        Write-Host "  $($group.Name): ✓ No active rules" -ForegroundColor Green
        $improvements += "$($group.Name) rules are properly disabled"
    }
}

# Check dangerous ports
Write-Host "`nDangerous Port Rules:" -ForegroundColor Cyan
$dangerousPorts = @(137,138,139,445,1900,5357,5358,2869,3702)
$portRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Where-Object {
    $portFilter = $_ | Get-NetFirewallPortFilter -EA 0
    $portFilter -and ($portFilter.LocalPort -in $dangerousPorts)
}

if ($portRules) {
    Write-Host "  Found $($portRules.Count) rules allowing dangerous ports:" -ForegroundColor Red
    $portRules | Select-Object DisplayName, @{N='Port';E={($_ | Get-NetFirewallPortFilter -EA 0).LocalPort}}, Action | Format-Table -AutoSize
    $issues += "Disable firewall rules for dangerous ports ($($portRules.Count) rules)"
} else {
    Write-Host "  ✓ No active rules for dangerous ports" -ForegroundColor Green
    $improvements += "Dangerous port rules are properly disabled"
}

# Check keyword-based dangerous rules
Write-Host "`nDangerous Keyword Rules:" -ForegroundColor Cyan
$keywordPatterns = @("*AllJoyn*", "*DIAL*", "*WFD*", "*UPnP*", "*SSDP*", "*Cast*", "*Direct*")
$keywordRules = @()
foreach ($pattern in $keywordPatterns) {
    $rules = Get-NetFirewallRule -DisplayName $pattern -EA 0 | Where-Object {$_.Enabled -eq "True" -and $_.Action -eq "Allow"}
    if ($rules) { $keywordRules += $rules }
}

if ($keywordRules) {
    Write-Host "  Found $($keywordRules.Count) dangerous keyword-based rules:" -ForegroundColor Yellow
    $keywordRules | Select-Object DisplayName, Direction, Action | Format-Table -AutoSize
    $issues += "Disable keyword-based dangerous rules ($($keywordRules.Count) rules)"
} else {
    Write-Host "  ✓ No dangerous keyword-based rules active" -ForegroundColor Green
    $improvements += "Keyword-based dangerous rules are disabled"
}

Write-Host ""

# 2. RDP CONFIGURATION ANALYSIS
Write-Host "2. RDP CONFIGURATION ANALYSIS" -ForegroundColor Yellow

# Check RDP Tailscale rule
$rdpTailscaleRule = Get-NetFirewallRule -DisplayName "*Tailscale*" -EA 0 | Where-Object {
    $portFilter = $_ | Get-NetFirewallPortFilter -EA 0
    $addressFilter = $_ | Get-NetFirewallAddressFilter -EA 0
    $portFilter -and $portFilter.LocalPort -eq 3389 -and 
    $addressFilter -and $addressFilter.RemoteAddress -match "100\.64\."
}

if ($rdpTailscaleRule) {
    Write-Host "RDP Tailscale Rule: ✓ Configured" -ForegroundColor Green
    $improvements += "RDP Tailscale-only rule is configured"
} else {
    Write-Host "RDP Tailscale Rule: ✗ Missing" -ForegroundColor Red
    $issues += "Create RDP rule for Tailscale network only"
}

# Check dangerous RDP rules
$dangerousRdpRules = Get-NetFirewallRule -Enabled True -Action Allow | Where-Object {
    $portFilter = $_ | Get-NetFirewallPortFilter -EA 0
    $addressFilter = $_ | Get-NetFirewallAddressFilter -EA 0
    $portFilter -and $portFilter.LocalPort -eq 3389 -and
    $addressFilter -and ($addressFilter.RemoteAddress -eq "Any" -or $addressFilter.RemoteAddress -eq "*" -or !$addressFilter.RemoteAddress -or $addressFilter.RemoteAddress -notmatch "100\.64\.")
}

if ($dangerousRdpRules) {
    Write-Host "Dangerous RDP Rules: $($dangerousRdpRules.Count) found" -ForegroundColor Red
    $dangerousRdpRules | Select-Object DisplayName, @{N='RemoteAddress';E={($_ | Get-NetFirewallAddressFilter -EA 0).RemoteAddress}} | Format-Table -AutoSize
    $issues += "Disable/modify dangerous RDP rules ($($dangerousRdpRules.Count) rules)"
} else {
    Write-Host "Dangerous RDP Rules: ✓ None found" -ForegroundColor Green
    $improvements += "No dangerous RDP rules active"
}

# Check RDP block rule
$rdpBlockRule = Get-NetFirewallRule -EA 0 | Where-Object {$_.DisplayName -match "Block.*RDP" -and $_.Action -eq "Block" -and $_.Enabled -eq "True"}
if ($rdpBlockRule) {
    Write-Host "RDP Block Rule: ✓ Configured" -ForegroundColor Green
    $improvements += "RDP block rule is configured"
} else {
    Write-Host "RDP Block Rule: ✗ Missing" -ForegroundColor Red
    $issues += "Create RDP block rule for internet access"
}

# Check Tailscale process rule
$tailscalePaths = @("${env:ProgramFiles}\Tailscale\tailscaled.exe", "${env:ProgramFiles(x86)}\Tailscale\tailscaled.exe", "${env:ProgramData}\Tailscale\tailscaled.exe")
$tailscalePath = $tailscalePaths | Where-Object {Test-Path $_} | Select-Object -First 1

if ($tailscalePath) {
    $tailscaleProcessRule = Get-NetFirewallRule -EA 0 | Where-Object {$_.Program -eq $tailscalePath -and $_.Action -eq "Allow" -and $_.Enabled -eq "True"}
    if ($tailscaleProcessRule) {
        Write-Host "Tailscale Process Rule: ✓ Configured ($tailscalePath)" -ForegroundColor Green
        $improvements += "Tailscale process rule is configured"
    } else {
        Write-Host "Tailscale Process Rule: ✗ Missing ($tailscalePath)" -ForegroundColor Red
        $issues += "Create Tailscale process allow rule"
    }
} else {
    Write-Host "Tailscale Installation: ✗ Not found" -ForegroundColor Red
    $issues += "Install Tailscale before running hardening script"
}

Write-Host ""

# 3. DANGEROUS SERVICES ANALYSIS
Write-Host "3. DANGEROUS SERVICES ANALYSIS" -ForegroundColor Yellow

$dangerousServices = @(
    @{Name="LanmanServer"; Desc="File and Printer Sharing"; Critical=$true},
    @{Name="WMPNetworkSvc"; Desc="Windows Media Player Network"; Critical=$false},
    @{Name="XboxNetApiSvc"; Desc="Xbox Live Networking"; Critical=$false},
    @{Name="DsSvc"; Desc="Data Sharing Service"; Critical=$false},
    @{Name="CDPSvc"; Desc="Connected Devices Platform"; Critical=$true}
)

Write-Host "Service Status:" -ForegroundColor Cyan
foreach ($svc in $dangerousServices) {
    $service = Get-Service -Name $svc.Name -EA 0
    if ($service) {
        $isRunning = $service.Status -eq "Running"
        $startupType = $service.StartType
        
        if ($isRunning -or $startupType -ne "Disabled") {
            $color = if ($svc.Critical) { "Red" } else { "Yellow" }
            Write-Host "  $($svc.Desc): $($service.Status)/$startupType" -ForegroundColor $color
            $issues += "Stop and disable $($svc.Desc) service"
        } else {
            Write-Host "  $($svc.Desc): ✓ Stopped/Disabled" -ForegroundColor Green
            $improvements += "$($svc.Desc) service is properly disabled"
        }
    } else {
        Write-Host "  $($svc.Desc): ✓ Not installed" -ForegroundColor Green
        $improvements += "$($svc.Desc) service is not installed"
    }
}

Write-Host ""

# 4. SMB AND NETBIOS ANALYSIS
Write-Host "4. SMB AND NETBIOS ANALYSIS" -ForegroundColor Yellow

# Check SMB registry settings
$smb1Setting = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -EA 0
$smb2Setting = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB2" -EA 0

Write-Host "SMB Configuration:" -ForegroundColor Cyan
if ($smb1Setting -and $smb1Setting.SMB1 -eq 0) {
    Write-Host "  SMB1: ✓ Disabled" -ForegroundColor Green
    $improvements += "SMB1 is disabled"
} else {
    Write-Host "  SMB1: ✗ Enabled or not set" -ForegroundColor Red
    $issues += "Disable SMB1 in registry"
}

if ($smb2Setting -and $smb2Setting.SMB2 -eq 0) {
    Write-Host "  SMB2: ✓ Disabled" -ForegroundColor Green
    $improvements += "SMB2 is disabled"
} else {
    Write-Host "  SMB2: ✗ Enabled or not set" -ForegroundColor Red
    $issues += "Disable SMB2 in registry"
}

# Check NetBIOS over TCP/IP
Write-Host "NetBIOS Configuration:" -ForegroundColor Cyan
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true}
$netbiosEnabled = 0
foreach ($adapter in $adapters) {
    if ($adapter.TcpipNetbiosOptions -ne 2) {
        $netbiosEnabled++
    }
}

if ($netbiosEnabled -eq 0) {
    Write-Host "  NetBIOS over TCP/IP: ✓ Disabled on all adapters" -ForegroundColor Green
    $improvements += "NetBIOS over TCP/IP is disabled"
} else {
    Write-Host "  NetBIOS over TCP/IP: ✗ Enabled on $netbiosEnabled adapter(s)" -ForegroundColor Red
    $issues += "Disable NetBIOS over TCP/IP on all network adapters"
}

# Check SMB Windows Features
Write-Host "SMB Windows Features:" -ForegroundColor Cyan
$smbFeatures = @("SMB1Protocol", "SMB1Protocol-Client", "SMB1Protocol-Server")
foreach ($feature in $smbFeatures) {
    $featureInfo = Get-WindowsOptionalFeature -Online -FeatureName $feature -EA 0
    if ($featureInfo) {
        if ($featureInfo.State -eq "Disabled") {
            Write-Host "  ${feature}: ✓ Disabled" -ForegroundColor Green
            $improvements += "$feature feature is disabled"
        } else {
            Write-Host "  ${feature}: ✗ $($featureInfo.State)" -ForegroundColor Red
            $issues += "Disable $feature Windows feature"
        }
    }
}

Write-Host ""

# 5. WSD/SSDP SERVICES ANALYSIS
Write-Host "5. WSD/SSDP SERVICES ANALYSIS" -ForegroundColor Yellow

$wsdServices = @(
    @{Name="SSDPSRV"; Desc="SSDP Discovery"},
    @{Name="upnphost"; Desc="UPnP Device Host"},
    @{Name="WSDSvc"; Desc="WSD Service"},
    @{Name="WSDPrintDevice"; Desc="WSD Print Device"}
)

Write-Host "WSD/SSDP Service Status:" -ForegroundColor Cyan
foreach ($svc in $wsdServices) {
    $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
    if (Test-Path $servicePath) {
        $startValue = Get-ItemProperty -Path $servicePath -Name "Start" -EA 0
        if ($startValue -and $startValue.Start -eq 4) {
            Write-Host "  $($svc.Desc): ✓ Disabled" -ForegroundColor Green
            $improvements += "$($svc.Desc) is disabled"
        } else {
            Write-Host "  $($svc.Desc): ✗ Not disabled (Start=$($startValue.Start))" -ForegroundColor Red
            $issues += "Disable $($svc.Desc) service"
        }
    } else {
        Write-Host "  $($svc.Desc): ✓ Not installed" -ForegroundColor Green
        $improvements += "$($svc.Desc) is not installed"
    }
}

# Check WSD/SSDP block rule
$wsdBlockRule = Get-NetFirewallRule -EA 0 | Where-Object {$_.DisplayName -match "Block.*WSD" -and $_.Action -eq "Block" -and $_.Enabled -eq "True"}
if ($wsdBlockRule) {
    Write-Host "WSD/SSDP Block Rule: ✓ Configured" -ForegroundColor Green
    $improvements += "WSD/SSDP block rule is configured"
} else {
    Write-Host "WSD/SSDP Block Rule: ✗ Missing" -ForegroundColor Red
    $issues += "Create WSD/SSDP block rule"
}

Write-Host ""

# 6. LISTENING PORTS ANALYSIS
Write-Host "6. LISTENING PORTS ANALYSIS" -ForegroundColor Yellow

$dangerousPorts = @(135,137,138,139,445,1900,5357,5358,2869,3389,3702)
$listeningPorts = Get-NetTCPConnection -State Listen | Where-Object {$_.LocalPort -in $dangerousPorts}

if ($listeningPorts) {
    Write-Host "Dangerous ports currently listening:" -ForegroundColor Red
    $portAnalysis = $listeningPorts | Select-Object LocalAddress,LocalPort,@{N='Process';E={(Get-Process -Id $_.OwningProcess -EA 0).Name}} | Sort-Object LocalPort
    $portAnalysis | Format-Table -AutoSize
    
    # Analyze each port
    foreach ($port in $dangerousPorts) {
        $portConnections = $listeningPorts | Where-Object {$_.LocalPort -eq $port}
        if ($portConnections) {
            $publicListeners = $portConnections | Where-Object {$_.LocalAddress -notmatch "^(127\.|::1|100\.)" -and $_.LocalAddress -ne "0.0.0.0" -and $_.LocalAddress -ne "::"}
            $allInterfaceListeners = $portConnections | Where-Object {$_.LocalAddress -eq "0.0.0.0" -or $_.LocalAddress -eq "::"}
            
            if ($publicListeners) {
                Write-Host "  Port ${port}: ✗ CRITICAL - Listening on public IP!" -ForegroundColor Magenta
                $issues += "Port ${port} is listening on public IP address"
            } elseif ($allInterfaceListeners) {
                Write-Host "  Port ${port}: ✗ DANGEROUS - Listening on all interfaces (0.0.0.0)" -ForegroundColor Red
                $issues += "Port ${port} is listening on all interfaces"
            } else {
                Write-Host "  Port ${port}: ⚠ Listening on local/private interfaces only" -ForegroundColor Yellow
            }
        }
    }
} else {
    Write-Host "✓ No dangerous ports listening" -ForegroundColor Green
    $improvements += "No dangerous ports are listening"
}

Write-Host ""

# 7. SUMMARY
Write-Host "7. SECURITY SUMMARY" -ForegroundColor Yellow

Write-Host "`nISSUES TO FIX:" -ForegroundColor Red
if ($issues.Count -eq 0) {
    Write-Host "  ✓ No issues found - system is properly hardened!" -ForegroundColor Green
} else {
    for ($i = 0; $i -lt $issues.Count; $i++) {
        Write-Host "  $($i + 1). $($issues[$i])" -ForegroundColor Red
    }
}

Write-Host "`nCURRENT SECURITY STRENGTHS:" -ForegroundColor Green
if ($improvements.Count -eq 0) {
    Write-Host "  No security improvements detected" -ForegroundColor Gray
} else {
    for ($i = 0; $i -lt $improvements.Count; $i++) {
        Write-Host "  ✓ $($improvements[$i])" -ForegroundColor Green
    }
}

# Calculate security score
$totalChecks = $issues.Count + $improvements.Count
$securityScore = if ($totalChecks -gt 0) { [math]::Round(($improvements.Count / $totalChecks) * 100) } else { 0 }
$scoreColor = if ($securityScore -ge 90) { "Green" } elseif ($securityScore -ge 70) { "Yellow" } else { "Red" }

Write-Host "`nSECURITY SCORE: $securityScore% ($($improvements.Count)/$totalChecks checks passed)" -ForegroundColor $scoreColor

if ($issues.Count -gt 0) {
    Write-Host "`nRECOMMENDATION: Run the hardening script to fix the identified issues." -ForegroundColor Yellow
} else {
    Write-Host "`nSYSTEM STATUS: Properly hardened for Tailscale-only access!" -ForegroundColor Green
}

Write-Host "`n=== ANALYSIS COMPLETED ===" -ForegroundColor Cyan