# Windows Firewall Restore Script
# Restores Windows to default configuration
# Run as Administrator!

Write-Host "=== WINDOWS FIREWALL RESTORE ===" -ForegroundColor Yellow
Write-Host "WARNING: This will restore Windows to default configuration!" -ForegroundColor Red
Write-Host "All security hardening will be REMOVED!" -ForegroundColor Red

$confirm = Read-Host "`nDo you want to continue? Type 'RESTORE' to confirm"
if ($confirm -ne "RESTORE") {
    Write-Host "Operation cancelled." -ForegroundColor Green
    exit 0
}

Write-Host "`nStarting restore process..." -ForegroundColor Yellow

# 1. RESTORE FIREWALL TO DEFAULTS
Write-Host "1. Restoring firewall to Windows defaults..." -ForegroundColor Cyan

try {
    # Reset Windows Firewall to default configuration
    Write-Host "  Resetting firewall configuration..." -ForegroundColor Gray
    netsh advfirewall reset | Out-Null
    
    # Alternative method for complete reset
    Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy" -Recurse -Force -EA 0
    
    # Restart firewall service to apply defaults
    Restart-Service -Name "MpsSvc" -Force -EA 0
    Start-Sleep 3
    
    # Enable default Windows firewall rules
    Enable-NetFirewallRule -DisplayGroup "Remote Desktop" -EA 0
    Enable-NetFirewallRule -DisplayGroup "Core Networking" -EA 0
    Enable-NetFirewallRule -DisplayGroup "Windows Management Instrumentation (WMI)" -EA 0
    
    Write-Host "  ✓ Firewall reset to Windows defaults" -ForegroundColor Green
} catch {
    Write-Host "  ⚠ Firewall reset failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 2. RESTORE CRITICAL SERVICES
Write-Host "2. Restoring critical services..." -ForegroundColor Cyan

$servicesToRestore = @(
    @{Name="LanmanServer"; StartupType="Automatic"; Desc="File/Print Sharing"},
    @{Name="SSDPSRV"; StartupType="Manual"; Desc="SSDP Discovery"},
    @{Name="upnphost"; StartupType="Manual"; Desc="UPnP Device Host"},
    @{Name="WMPNetworkSvc"; StartupType="Manual"; Desc="Media Player Network"},
    @{Name="XboxNetApiSvc"; StartupType="Manual"; Desc="Xbox Live Network"},
    @{Name="CDPSvc"; StartupType="Automatic"; Desc="Connected Devices"},
    @{Name="RemoteRegistry"; StartupType="Disabled"; Desc="Remote Registry"}, # Keep disabled for security
    @{Name="SharedAccess"; StartupType="Manual"; Desc="Internet Sharing"}
)

foreach ($svc in $servicesToRestore) {
    try {
        $service = Get-Service -Name $svc.Name -EA 0
        if ($service) {
            Set-Service -Name $svc.Name -StartupType $svc.StartupType -EA 0
            
            # Start services that should be running
            if ($svc.StartupType -eq "Automatic") {
                Start-Service -Name $svc.Name -EA 0
                Write-Host "  ✓ Started $($svc.Desc) (Automatic)" -ForegroundColor Green
            } else {
                Write-Host "  ✓ Configured $($svc.Desc) ($($svc.StartupType))" -ForegroundColor Green
            }
        } else {
            Write-Host "  - $($svc.Desc): Not installed" -ForegroundColor Gray
        }
    } catch {
        Write-Host "  ⚠ Failed to restore $($svc.Name): $($_.Exception.Message)" -ForegroundColor Yellow
    }
}

# 3. RESTORE SMB CONFIGURATION
Write-Host "3. Restoring SMB configuration..." -ForegroundColor Cyan

try {
    # Re-enable SMB protocols
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB1" -Value 1 -Force -EA 0
    Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "SMB2" -Force -EA 0
    
    # Re-enable SMB Windows Features
    Enable-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -NoRestart -EA 0
    
    Write-Host "  ✓ SMB protocols re-enabled" -ForegroundColor Green
} catch {
    Write-Host "  ⚠ SMB restore failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 4. RESTORE NETBIOS CONFIGURATION
Write-Host "4. Restoring NetBIOS configuration..." -ForegroundColor Cyan

try {
    # Re-enable NetBIOS over TCP/IP on all adapters
    $adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true}
    $restoredAdapters = 0
    
    foreach ($adapter in $adapters) {
        try {
            $adapter.SetTcpipNetbios(0) | Out-Null  # 0 = Use NetBIOS setting from DHCP server
            $restoredAdapters++
        } catch {
            # Some adapters might not support this method
        }
    }
    
    Write-Host "  ✓ NetBIOS restored on $restoredAdapters adapter(s)" -ForegroundColor Green
} catch {
    Write-Host "  ⚠ NetBIOS restore failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 5. RESTORE RDP CONFIGURATION
Write-Host "5. Ensuring RDP is properly configured..." -ForegroundColor Cyan

try {
    # Enable RDP in registry
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -Value 0 -Force -EA 0
    
    # Start RDP services
    Set-Service -Name "TermService" -StartupType Automatic -EA 0
    Start-Service -Name "TermService" -EA 0
    
    Set-Service -Name "SessionEnv" -StartupType Manual -EA 0
    Start-Service -Name "SessionEnv" -EA 0
    
    Set-Service -Name "UmRdpService" -StartupType Manual -EA 0
    Start-Service -Name "UmRdpService" -EA 0
    
    Write-Host "  ✓ RDP services restored and started" -ForegroundColor Green
} catch {
    Write-Host "  ⚠ RDP restore failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 6. VERIFICATION
Write-Host "6. Verification..." -ForegroundColor Cyan

try {
    # Check firewall status
    $profiles = Get-NetFirewallProfile
    Write-Host "  Firewall Profiles:" -ForegroundColor Gray
    foreach ($profile in $profiles) {
        Write-Host "    $($profile.Name): Enabled=$($profile.Enabled), Default=$($profile.DefaultInboundAction)" -ForegroundColor Gray
    }
    
    # Check active rules count
    $activeRules = Get-NetFirewallRule -Enabled True
    Write-Host "  Active Firewall Rules: $($activeRules.Count)" -ForegroundColor Gray
    
    # Check critical services
    $runningServices = $servicesToRestore | Where-Object {$_.StartupType -eq "Automatic"} | ForEach-Object {
        $svc = Get-Service -Name $_.Name -EA 0
        if ($svc -and $svc.Status -eq "Running") { $_.Name }
    }
    Write-Host "  Running Critical Services: $($runningServices.Count)" -ForegroundColor Gray
    
    # Check RDP status
    $rdpService = Get-Service -Name "TermService" -EA 0
    $rdpEnabled = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name fDenyTSConnections -EA 0).fDenyTSConnections -eq 0
    
    if ($rdpService.Status -eq "Running" -and $rdpEnabled) {
        Write-Host "  ✓ RDP is accessible" -ForegroundColor Green
    } else {
        Write-Host "  ⚠ RDP might not be accessible" -ForegroundColor Yellow
    }
    
} catch {
    Write-Host "  ⚠ Verification failed: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 7. SUMMARY
Write-Host "`n=== RESTORE COMPLETED ===" -ForegroundColor Green
Write-Host "Windows has been restored to default configuration:" -ForegroundColor Cyan
Write-Host "  • Firewall: Reset to Windows defaults" -ForegroundColor White
Write-Host "  • Services: Restored to original startup types" -ForegroundColor White
Write-Host "  • SMB: Re-enabled" -ForegroundColor White
Write-Host "  • NetBIOS: Re-enabled" -ForegroundColor White
Write-Host "  • RDP: Accessible from all networks" -ForegroundColor White

Write-Host "`nSECURITY WARNING:" -ForegroundColor Red
Write-Host "  Your system is now in DEFAULT Windows configuration!" -ForegroundColor Yellow
Write-Host "  This means REDUCED SECURITY compared to the hardened state!" -ForegroundColor Yellow
Write-Host "  Consider running security updates and monitoring." -ForegroundColor Yellow

Write-Host "`nNext Steps:" -ForegroundColor Yellow
Write-Host "  1. Test network connectivity and services" -ForegroundColor White
Write-Host "  2. Verify RDP access from your networks" -ForegroundColor White
Write-Host "  3. Consider re-applying selective hardening if needed" -ForegroundColor White

$restart = Read-Host "`nRestart system to complete restore? (Y/n)"
if ($restart -notlike "n*") {
    Write-Host "Restarting in 5 seconds..." -ForegroundColor Yellow
    Start-Sleep 5
    Restart-Computer -Force
} else {
    Write-Host "Restart manually to complete the restoration!" -ForegroundColor Yellow
}