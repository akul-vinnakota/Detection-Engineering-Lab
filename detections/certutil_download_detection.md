# Certutil Download Detection

## Detection Summary

- **Platform:** Windows
- **Log source:** Sysmon-style process creation events
- **MITRE ATT&CK:** T1105 — Ingress Tool Transfer
- **Severity:** High
- **Events processed:** Three
- **Alerts generated:** One
- **Automated tests:** Four passed

## Detection Logic

The detector identifies `certutil.exe` processes that contain a web URL and command-line arguments commonly associated with downloading files.

Attackers may abuse legitimate Windows utilities such as Certutil to transfer tools or payloads while blending in with trusted system binaries.

## Investigation Guidance

1. Identify the user and parent process that launched Certutil.
2. Review the source URL and downloaded file path.
3. Verify whether the download was authorized.
4. Inspect the downloaded file with endpoint-security tools.
5. Search for related process execution after the download.
6. Review network activity to the source domain or IP.
7. Isolate the endpoint if malicious activity is confirmed.

## False Positives

- Authorized administrative downloads
- Certificate troubleshooting
- Approved software distribution
- Legitimate security testing
