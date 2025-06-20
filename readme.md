# Windows Firewall Scripts

This repository provides PowerShell scripts to harden a Windows PC by blocking or disabling as many unnecessary internet services as possible. The goal is to minimize the system's attack surface on the internet.

These scripts are designed for systems where Tailscale is already installed and remote access is performed via RDP over the Tailscale network.

## File Overview

- **firewall-configuration.ps1**
  - Applies a restrictive Windows Firewall configuration. Only essential rules are enabled; all other inbound connections are blocked. By default, only Tailscale and RDP over Tailscale are allowed.

- **firewall-restore.ps1**
  - Restores the default Windows Firewall configuration and re-enables critical Windows services. Use this script to revert the restrictive settings if needed.

- **firewall-verification.ps1**
  - Verifies the current firewall configuration and the status of critical services. The script checks that only the intended rules are active, critical ports are blocked, and potentially dangerous Windows services are disabled. A security assessment is displayed at the end.

## Usage

1. **Configuration:**
   - Run `firewall-configuration.ps1` as administrator to apply the restrictive firewall rules.
2. **Verification:**
   - After a reboot, run `firewall-verification.ps1` to check the security status.
3. **Restore:**
   - If needed, run `firewall-restore.ps1` to restore the default configuration and services.

**Note:**
All scripts must be executed with administrative privileges.

Copyright © softworx by Andreas Schwab. Licensed under the GNU General Public License (GPL).