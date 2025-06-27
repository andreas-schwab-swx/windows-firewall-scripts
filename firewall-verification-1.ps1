# Firewall Security Verification - Compact
Write-Host "FIREWALL AND SERVICES SECURITY CHECK" -ForegroundColor Green

# 1. RDP Rules Check
$rdpAllow = Get-NetFirewallRule -DisplayName "*RDP*" | Where-Object {$_.Action -eq "Allow" -and $_.Enabled -eq "True"}
$rdpTailscale = $rdpAllow | Get-NetFirewallAddressFilter | Where-Object {$_.RemoteAddress -like "100.*"}
Write-Host "RDP Tailscale Rule: $(if($rdpTailscale){'✓ OK'}else{'✗ MISSING'})" -ForegroundColor $(if($rdpTailscale){'Green'}else{'Red'})

# 2. Dangerous Ports Check
$badPorts = Get-NetTCPConnection -State Listen | Where-Object {$_.LocalPort -in @(445,139,135,1900,5357)}
$blockedPorts = Get-NetFirewallRule | Where-Object {$_.DisplayName -like "Block-*" -and $_.Action -eq "Block" -and $_.Enabled -eq "True"}
Write-Host "Dangerous Ports Listening: $($badPorts.Count) (Expected for Windows)" -ForegroundColor Yellow
if($badPorts.Count -gt 0) { 
    $badPorts | Select-Object LocalPort,LocalAddress,@{N='Process';E={(Get-Process -Id $_.OwningProcess -EA 0).Name}} | Format-Table -AutoSize
}
Write-Host "Firewall Block Rules: $($blockedPorts.Count)" -ForegroundColor $(if($blockedPorts.Count -ge 5){'Green'}else{'Red'})
if($blockedPorts.Count -gt 0) {
    $blockedPorts | Select-Object DisplayName,Direction,Action | Sort-Object DisplayName | Format-Table -AutoSize
}

# 3. Tailscale Status
$tsIP = Get-NetIPAddress | Where-Object {$_.InterfaceAlias -like "*Tailscale*" -and $_.AddressFamily -eq "IPv4"}
Write-Host "Tailscale IP: $(if($tsIP){$tsIP.IPAddress + ' ✓'}else{'✗ NOT FOUND'})" -ForegroundColor $(if($tsIP){'Green'}else{'Red'})

# 4. Critical Services
$services = 'LanmanServer','SSDPSRV','upnphost','WMPNetworkSvc','XboxNetApiSvc'
$stopped = ($services | ForEach-Object {Get-Service $_ -EA 0} | Where-Object {$_.Status -eq 'Stopped'}).Count
Write-Host "Dangerous Services Stopped: $stopped/$($services.Count)" -ForegroundColor $(if($stopped -eq $services.Count){'Green'}else{'Yellow'})

# 5. Firewall Status
$fwStatus = Get-NetFirewallProfile | Where-Object {$_.Enabled -eq $false}
Write-Host "Firewall Status: $(if(!$fwStatus){'✓ ENABLED'}else{'✗ DISABLED'})" -ForegroundColor $(if(!$fwStatus){'Green'}else{'Red'})

# 6. Active Rules Count
$activeRules = (Get-NetFirewallRule -Enabled True).Count
$allowRules = Get-NetFirewallRule -Enabled True -Action Allow
Write-Host "Active Rules: $activeRules (Allow: $($allowRules.Count), Block: $($activeRules - $allowRules.Count))" -ForegroundColor $(if($activeRules -lt 50){'Green'}else{'Yellow'})
Write-Host "`nActive Allow Rules:" -ForegroundColor Cyan
$allowRules | Select-Object DisplayName,Direction,@{N='Port';E={
    $portFilter = $_ | Get-NetFirewallPortFilter -EA 0
    if($portFilter.LocalPort) { $portFilter.LocalPort } else { "Any" }
}} | Sort-Object DisplayName | Format-Table -AutoSize

# Security Score
$score = 0
if($rdpTailscale) {$score += 30}
if($blockedPorts.Count -ge 5) {$score += 25}
if($tsIP) {$score += 20}
if($stopped -eq $services.Count) {$score += 15}
if(!$fwStatus) {$score += 10}

Write-Host "`nSECURITY SCORE: $score/100" -ForegroundColor $(if($score -ge 80){'Green'}elseif($score -ge 60){'Yellow'}else{'Red'})
Write-Host "Status: $(if($score -ge 80){'SECURE'}elseif($score -ge 60){'ACCEPTABLE'}else{'INSECURE'})" -ForegroundColor $(if($score -ge 80){'Green'}elseif($score -ge 60){'Yellow'}else{'Red'})