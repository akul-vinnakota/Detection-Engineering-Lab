# Microsoft Defender Exclusion Tampering Detection

## Detection Summary

- **Platform:** Windows
- **Log source:** Sysmon-style process creation events
- **MITRE ATT&CK:** T1685 — Disable or Modify Tools
- **Tactic:** Stealth
- **Severity:** High
- **Events processed:** Three
- **Alerts generated:** One
- **Automated tests:** Four passed

## Detection Logic

The detector identifies PowerShell processes using `Add-MpPreference` or `Set-MpPreference` with Defender exclusion parameters.

Monitored exclusion types include:

- Excluded paths
- Excluded processes
- Excluded file extensions
- Excluded IP addresses

Attackers may add exclusions to prevent security tools from inspecting malicious files or processes.

## Investigation Guidance

1. Identify the user and parent process that executed the command.
2. Review the excluded path, process, extension, or IP address.
3. Confirm whether the change was approved by security administrators.
4. Search for files or processes operating inside the excluded location.
5. Remove unauthorized exclusions.
6. Run an endpoint scan and investigate related activity.

## False Positives

- Approved security administration
- Enterprise software installation
- Authorized endpoint-management activity
- Documented troubleshooting procedures
