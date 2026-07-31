# Suspicious LSASS Access Detection

## Detection Summary

- **Platform:** Windows
- **Log source:** Sysmon process-access events
- **Event ID:** 10
- **MITRE ATT&CK:** T1003.001 — LSASS Memory
- **Tactic:** Credential Access
- **Severity:** High
- **Events processed:** Three
- **Alerts generated:** One
- **Automated tests:** Four passed

## Detection Logic

The detector identifies Sysmon Event ID 10 activity where a process requests suspicious access rights to `lsass.exe`.

LSASS stores authentication-related information in memory. Unauthorized access may indicate an attempt to obtain credentials, password hashes, or authentication tokens.

## Investigation Guidance

1. Identify the source process and its file location.
2. Verify whether the executable is signed and approved.
3. Review the user account and parent process.
4. Search for related process creation and network events.
5. Isolate the endpoint if credential dumping is suspected.
6. Reset potentially exposed credentials.
7. Investigate lateral movement involving the affected account.

## False Positives

- Endpoint security software
- Approved debugging or diagnostic tools
- Credential-management applications
- Authorized penetration testing
