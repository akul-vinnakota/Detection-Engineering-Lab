# Detection Results

## PowerShell Encoded Command Detection

- **Rule:** PowerShell Encoded Command Execution
- **Platform:** Windows
- **Log source:** Sysmon-style process creation events
- **MITRE ATT&CK:** T1059.001
- **Severity:** Medium
- **Test events processed:** 2
- **Alerts generated:** 1
- **Automated tests:** 3 passed

The detector identified the encoded PowerShell event while ignoring normal PowerShell and non-PowerShell activity.
