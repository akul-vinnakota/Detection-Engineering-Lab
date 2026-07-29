# Suspicious Scheduled Task Detection

## Detection Summary

- **Platform:** Windows
- **Log source:** Sysmon-style process creation events
- **MITRE ATT&CK:** T1053.005 — Scheduled Task
- **Tactics:** Persistence and Privilege Escalation
- **Severity:** High
- **Events processed:** Three
- **Alerts generated:** One
- **Automated tests:** Four passed

## Detection Logic

The detector identifies `schtasks.exe` creating a new scheduled task when the command contains suspicious interpreters, download URLs, or user-writable locations such as AppData and Temp.

## Investigation Guidance

1. Identify the task name, creator, schedule, and execution command.
2. Review the parent process and user account responsible.
3. Inspect any referenced scripts or executable files.
4. Check whether the task executed on additional systems.
5. Disable the task and isolate the endpoint when malicious activity is confirmed.

## False Positives

- Approved administrative scripts
- Enterprise software deployment
- Authorized maintenance tasks
- Legitimate applications using user-writable directories
