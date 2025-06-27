# Windows Firewall Security Configuration for Tailscale-only RDP
# Language Independent - Consistent with Analysis Script  
# Run as Administrator!

Write-Host "=== WINDOWS SECURITY HARDENING ===" -ForegroundColor Green
Write-Host "Starting security configuration..." -ForegroundColor Yellow
Write-Host "Errors will be displayed for transparency and debugging." -ForegroundColor Gray
Write-Host ""

$changesCount = 0
$errorsCount = 0

# 1. DISABLE DANGEROUS FIREWALL RULES (matching Analyze-Script approach)
Write-Host "1. DISABLING DANGEROUS FIREWALL RULES" -ForegroundColor Yellow

# Disable dangerous groups by Resource String IDs (same as Analyze-Script)
$dangerousGroups = @(
    @{ID="@FirewallAPI.dll,-32752"; Name="Network Discovery"},
    @{ID="@FirewallAPI.dll,-28502"; Name="File and Printer Sharing"},
    @{ID="@FirewallAPI.dll,-33002"; Name="Remote Assistance"}
)

Write-Host "Disabling dangerous rule groups:" -ForegroundColor Cyan
foreach ($group in $dangerousGroups) {
    try {
        $rules = Get-NetFirewallRule -Group $group.ID -Enabled True -Action Allow
        if ($rules) {
            $count = $rules.Count
            Write-Host "  Disabling $($group.Name): $count rules" -ForegroundColor Yellow
            $rules | Disable-NetFirewallRule
            $changesCount += $count
        } else {
            Write-Host "  $($group.Name): Already disabled" -ForegroundColor Green
        }
    } catch {
        Write-Host "  ERROR disabling $($group.Name): $($_.Exception.Message)" -ForegroundColor Red
        $errorsCount++
    }
}

# Disable dangerous port rules (same logic as Analyze-Script)
Write-Host "Disabling dangerous port rules:" -ForegroundColor Cyan
try {
    $dangerousPorts = @(137,138,139,445,1900,5357,5358,2869,3702)
    $portRules = Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Where-Object {
        $portFilter = $_ | Get-NetFirewallPortFilter -EA 0
        $portFilter -and ($portFilter.LocalPort -in $dangerousPorts)
    }

    if ($portRules) {
        Write-Host "  Disabling $($portRules.Count) dangerous port rules" -ForegroundColor Yellow
        $portRules | Disable-NetFirewallRule
        $changesCount += $portRules.Count
    } else {
        Write-Host "  No dangerous port rules found" -ForegroundColor Green
    }
} catch {
    Write-Host "  ERROR disabling port rules: $($_.Exception.Message)" -ForegroundColor Red
    $errorsCount++
}

# Disable keyword-based dangerous rules (same patterns as Analyze-Script)
Write-Host "Disabling keyword-based dangerous rules:" -ForegroundColor Cyan
try {
    $keywordPatterns = @("*AllJoyn*", "*DIAL*", "*WFD*", "*UPnP*", "*SSDP*", "*Cast*", "*Direct*")
    $keywordRules = @()
    foreach ($pattern in $keywordPatterns) {
        try {
            $rules = Get-NetFirewallRule -DisplayName $pattern | Where-Object {$_.Enabled -eq "True" -and $_.Action -eq "Allow"}
            if ($rules) { $keywordRules += $rules }
        } catch {
            Write-Host "    WARNING: No rules found for pattern $pattern" -ForegroundColor DarkYellow
        }
    }

    if ($keywordRules) {
        Write-Host "  Disabling $($keywordRules.Count) keyword-based rules" -ForegroundColor Yellow
        $keywordRules | Disable-NetFirewallRule
        $changesCount += $keywordRules.Count
    } else {
        Write-Host "  No keyword-based dangerous rules found" -ForegroundColor Green
    }
} catch {
    Write-Host "  ERROR disabling keyword rules: $($_.Exception.Message)" -ForegroundColor Red
    $errorsCount++
}

Write-Host ""

# 2. CONFIGURE RDP FOR TAILSCALE ONLY (matching Analyze-Script checks)
Write-Host "2. CONFIGURING RDP FOR TAILSCALE ONLY" -ForegroundColor Yellow

# Disable existing dangerous RDP rules
Write-Host "Disabling dangerous RDP rules:" -ForegroundColor Cyan
$dangerousRdpRules = Get-NetFirewallRule -Enabled True -Action Allow -EA 0 | Where-Object {
    $portFilter = $_ | Get-NetFirewallPortFilter -EA 0
    $addressFilter = $_ | Get-NetFirewallAddressFilter -EA 0
    $portFilter -and $portFilter.LocalPort -eq 3389 -and
    $addressFilter -and ($addressFilter.RemoteAddress -eq "Any" -or $addressFilter.RemoteAddress -eq "*" -or !$addressFilter.RemoteAddress -or $addressFilter.RemoteAddress -notmatch "100\.64\.")
}

if ($dangerousRdpRules) {
    Write-Host "  Disabling $($dangerousRdpRules.Count) dangerous RDP rules" -ForegroundColor Yellow
    $dangerousRdpRules | Disable-NetFirewallRule -EA 0
    $changesCount += $dangerousRdpRules.Count
} else {
    Write-Host "  No dangerous RDP rules found" -ForegroundColor Green
}

# Create RDP Tailscale rule
Write-Host "Creating RDP Tailscale-only rule:" -ForegroundColor Cyan
$existingTailscaleRdp = Get-NetFirewallRule -EA 0 | Where-Object {
    $portFilter = $_ | Get-NetFirewallPortFilter -EA 0
    $addressFilter = $_ | Get-NetFirewallAddressFilter -EA 0
    $portFilter -and $portFilter.LocalPort -eq 3389 -and 
    $addressFilter -and $addressFilter.RemoteAddress -match "100\.64\."
}

if (!$existingTailscaleRdp) {
    New-NetFirewallRule -DisplayName "RDP-Tailscale-Only" -Direction Inbound -Protocol TCP -LocalPort 3389 -RemoteAddress "100.64.0.0/10" -Action Allow -EA 0
    Write-Host "  ✓ Created RDP Tailscale-only rule" -ForegroundColor Green
    $changesCount++
} else {
    Write-Host "  RDP Tailscale rule already exists" -ForegroundColor Green
}

# Create RDP block rule
Write-Host "Creating RDP block rule:" -ForegroundColor Cyan
$existingRdpBlock = Get-NetFirewallRule -EA 0 | Where-Object {$_.DisplayName -match "Block.*RDP" -and $_.Action -eq "Block" -and $_.Enabled -eq "True"}
if (!$existingRdpBlock) {
    New-NetFirewallRule -DisplayName "RDP-Block-Internet" -Direction Inbound -Protocol TCP -LocalPort 3389 -InterfaceType RemoteAccess -Action Block -EA 0
    Write-Host "  ✓ Created RDP block rule" -ForegroundColor Green
    $changesCount++
} else {
    Write-Host "  RDP block rule already exists" -ForegroundColor Green
}

# Configure Tailscale process rule
Write-Host "Configuring Tailscale process rule:" -ForegroundColor Cyan
$tailscalePaths = @("${env:ProgramFiles}\Tailscale\tailscaled.exe", "${env:ProgramFiles(x86)}\Tailscale\tailscaled.exe", "${env:ProgramData}\Tailscale\tailscaled.exe")
$tailscalePath = $tailscalePaths | Where-Object {Test-Path $_} | Select-Object -First 1

if ($tailscalePath) {
    $existingTailscaleRule = Get-NetFirewallRule -EA 0 | Where-Object {$_.Program -eq $tailscalePath -and $_.Action -eq "Allow" -and $_.Enabled -eq "True"}
    if (!$existingTailscaleRule) {
        New-NetFirewallRule -DisplayName "Tailscale-Process" -Direction Inbound -Program $tailscalePath -Action Allow -EA 0
        Write-Host "  ✓ Created Tailscale process rule ($tailscalePath)" -ForegroundColor Green
        $changesCount++
    } else {
        Write-Host "  Tailscale process rule already exists" -ForegroundColor Green
    }
} else {
    Write-Host "  ⚠ Tailscale not found - install Tailscale first!" -ForegroundColor Red
}

Write-Host ""

# 3. DISABLE DANGEROUS SERVICES (same list as Analyze-Script)
Write-Host "3. DISABLING DANGEROUS SERVICES" -ForegroundColor Yellow

$dangerousServices = @(
    @{Name="LanmanServer"; Desc="File and Printer Sharing"},
    @{Name="WMPNetworkSvc"; Desc="Windows Media Player Network"},
    @{Name="XboxNetApiSvc"; Desc="Xbox Live Networking"},
    @{Name="DsSvc"; Desc="Data Sharing Service"},
    @{Name="CDPSvc"; Desc="Connected Devices Platform"}
)

Write-Host "Service configuration:" -ForegroundColor Cyan
foreach ($svc in $dangerousServices) {
    $service = Get-Service -Name $svc.Name -EA 0
    if ($service) {
        $needsChange = $service.Status -eq "Running" -or $service.StartType -ne "Disabled"
        if ($needsChange) {
            Write-Host "  Stopping and disabling $($svc.Desc)" -ForegroundColor Yellow
            Stop-Service -Name $svc.Name -Force -EA 0
            Set-Service -Name $svc.Name -StartupType Disabled -EA 0
            $changesCount++
        } else {
            Write-Host "  $($svc.Desc): Already stopped/disabled" -ForegroundColor Green
        }
    } else {
        Write-Host "  $($svc.Desc): Not installed" -ForegroundColor Green
    }
}

Write-Host ""

# 4. DISABLE SMB AND NETBIOS (matching Analyze-Script checks)
Write-Host "4. DISABLING SMB AND NETBIOS" -ForegroundColor Yellow

# SMB registry settings
Write-Host "SMB configuration:" -ForegroundColor Cyan
$smb1Setting = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -EA 0
$smb2Setting = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB2" -EA 0

if (!$smb1Setting -or $smb1Setting.SMB1 -ne 0) {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 0 -Force -EA 0
    Write-Host "  ✓ SMB1 disabled" -ForegroundColor Green
    $changesCount++
} else {
    Write-Host "  SMB1: Already disabled" -ForegroundColor Green
}

if (!$smb2Setting -or $smb2Setting.SMB2 -ne 0) {
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB2" -Value 0 -Force -EA 0
    Write-Host "  ✓ SMB2 disabled" -ForegroundColor Green
    $changesCount++
} else {
    Write-Host "  SMB2: Already disabled" -ForegroundColor Green
}

# NetBIOS over TCP/IP (same logic as Analyze-Script)
Write-Host "NetBIOS configuration:" -ForegroundColor Cyan
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true}
$netbiosChanges = 0
foreach ($adapter in $adapters) {
    if ($adapter.TcpipNetbiosOptions -ne 2) {
        $adapter.SetTcpipNetbios(2) | Out-Null
        $netbiosChanges++
    }
}

if ($netbiosChanges -gt 0) {
    Write-Host "  ✓ NetBIOS over TCP/IP disabled on $netbiosChanges adapter(s)" -ForegroundColor Green
    $changesCount += $netbiosChanges
} else {
    Write-Host "  NetBIOS over TCP/IP: Already disabled on all adapters" -ForegroundColor Green
}

# SMB Windows Features (same as Analyze-Script)
Write-Host "SMB Windows Features:" -ForegroundColor Cyan
$smbFeatures = @("SMB1Protocol", "SMB1Protocol-Client", "SMB1Protocol-Server")
foreach ($feature in $smbFeatures) {
    $featureInfo = Get-WindowsOptionalFeature -Online -FeatureName $feature -EA 0
    if ($featureInfo -and $featureInfo.State -ne "Disabled") {
        Disable-WindowsOptionalFeature -Online -FeatureName $feature -NoRestart -EA 0
        Write-Host "  ✓ ${feature} disabled" -ForegroundColor Green
        $changesCount++
    } else {
        Write-Host "  ${feature}: Already disabled" -ForegroundColor Green
    }
}

Write-Host ""

# 5. DISABLE WSD/SSDP SERVICES (matching Analyze-Script)
Write-Host "5. DISABLING WSD/SSDP SERVICES" -ForegroundColor Yellow

$wsdServices = @(
    @{Name="SSDPSRV"; Desc="SSDP Discovery"},
    @{Name="upnphost"; Desc="UPnP Device Host"},
    @{Name="WSDSvc"; Desc="WSD Service"},
    @{Name="WSDPrintDevice"; Desc="WSD Print Device"}
)

Write-Host "WSD/SSDP service configuration:" -ForegroundColor Cyan
foreach ($svc in $wsdServices) {
    $servicePath = "HKLM:\SYSTEM\CurrentControlSet\Services\$($svc.Name)"
    if (Test-Path $servicePath) {
        $startValue = Get-ItemProperty -Path $servicePath -Name "Start" -EA 0
        if (!$startValue -or $startValue.Start -ne 4) {
            Set-ItemProperty -Path $servicePath -Name "Start" -Value 4 -Force -EA 0
            Write-Host "  ✓ $($svc.Desc) disabled" -ForegroundColor Green
            $changesCount++
        } else {
            Write-Host "  $($svc.Desc): Already disabled" -ForegroundColor Green
        }
    } else {
        Write-Host "  $($svc.Desc): Not installed" -ForegroundColor Green
    }
}

# Create WSD/SSDP block rule
Write-Host "WSD/SSDP block rule:" -ForegroundColor Cyan
$existingWsdBlock = Get-NetFirewallRule -EA 0 | Where-Object {$_.DisplayName -match "Block.*WSD" -and $_.Action -eq "Block" -and $_.Enabled -eq "True"}
if (!$existingWsdBlock) {
    New-NetFirewallRule -DisplayName "Block-WSD-SSDP" -Direction Inbound -Protocol UDP -LocalPort 5357 -Action Block -EA 0
    Write-Host "  ✓ Created WSD/SSDP block rule" -ForegroundColor Green
    $changesCount++
} else {
    Write-Host "  WSD/SSDP block rule already exists" -ForegroundColor Green
}

Write-Host ""

# 6. SUMMARY
Write-Host "6. HARDENING SUMMARY" -ForegroundColor Yellow

Write-Host "Configuration completed!" -ForegroundColor Green
Write-Host "Total changes made: $changesCount" -ForegroundColor Cyan
Write-Host "Total errors encountered: $errorsCount" -ForegroundColor $(if($errorsCount -gt 0){'Red'}else{'Green'})

if ($errorsCount -gt 0) {
    Write-Host "`nWARNING: Some operations failed. Check error messages above." -ForegroundColor Red
    Write-Host "You may need to run the script again or investigate manually." -ForegroundColor Yellow
}

if ($changesCount -gt 0) {
    Write-Host "`nIMPORTANT: System restart recommended to apply all changes." -ForegroundColor Yellow
    Write-Host "Run the analysis script again after restart to verify configuration." -ForegroundColor Yellow
} else {
    Write-Host "`nSystem was already properly configured." -ForegroundColor Green
}

Write-Host "`nPress any key to restart the computer..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Restart-Computer -Force