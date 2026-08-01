# Suspicious Remote Service Execution Detection

## Detection Summary

- **Platform:** Windows
- **Log source:** Windows System service events
- **Event ID:** 7045
- **MITRE ATT&CK:** T1021.002 and T1569.002
- **Tactics:** Lateral Movement and Execution
- **Severity:** High
- **Events processed:** Three
- **Alerts generated:** One
- **Automated tests:** Four passed

## Detection Logic

The detector identifies Windows service-creation events associated with PsExec-style remote execution.

It checks for suspicious service names such as `PSEXESVC` and `PAExec`, along with executable paths commonly associated with remote administrative execution.

Attackers may create services on remote systems to execute commands using valid administrative credentials.

## Investigation Guidance

1. Identify the source computer and user account.
2. Confirm whether PsExec or PAExec usage was authorized.
3. Review the newly created service name and executable path.
4. Search for SMB connections and administrative-share access.
5. Review authentication events involving the source account.
6. Check for related process execution on the destination system.
7. Isolate affected systems if unauthorized lateral movement is confirmed.

## False Positives

- Authorized systems administration
- Help-desk troubleshooting
- Enterprise software deployment
- Approved penetration testing
