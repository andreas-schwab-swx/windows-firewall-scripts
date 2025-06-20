# Windows Firewall Scripts

This repository contains PowerShell scripts to harden a Windows PC by blocking or disabling as many unnecessary internet services as possible. The goal is to minimize the system's attack surface on the internet.

The script assumes that tailscale is already installed on the system and that you are accessing the Windows PC via RDP over the tailscale connection. 

## File Overview

- **firewall-configuration.ps1**
  - Configures the Windows Firewall in a restrictive way. Only necessary rules are enabled; all other connections are blocked. The only allowed connections are tailscale and RDP over the tailscale connection.

- **firewall-restore.ps1**
  - Restores the default Windows Firewall configuration and enables critical Windows services. Useful if you want to revert the restrictive settings.

- **firewall-verification.ps1**
  - Checks the current firewall configuration and critical services. The script verifies that only allowed rules are active, critical ports are blocked, and dangerous Windows services are disabled. At the end, a security assessment is displayed.

## Usage

1. **Configuration:**
   - Run `firewall-configuration.ps1` as administrator to apply the restrictive firewall rules.
2. **Verification:**
   - After a reboot, run `firewall-verification.ps1` to check the security status.
3. **Restore:**
   - If needed, run `firewall-restore.ps1` to restore the default configuration.

**Note:**
All scripts must be executed with administrative privileges.

Copyright by softworx by andreas schwab under the GNU ...