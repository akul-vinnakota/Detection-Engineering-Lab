# Detection Engineering Lab

A detection-as-code cybersecurity project using Sigma, Python, Sysmon, and Wazuh to create, test, and document threat detections.

## Project Goals

- Develop portable Sigma detection rules
- Analyze Windows, Linux, and network security logs
- Map detections to MITRE ATT&CK techniques
- Test detections against safe sample events
- Document alert investigations and remediation steps
- Integrate detections with Sysmon and Wazuh

## Core Tools

- Sigma
- Python
- Sysmon
- Wazuh

## Current Detections

| Detection | Platform | MITRE ATT&CK | Severity | Status |
|---|---|---|---|---|
| PowerShell Encoded Command Execution | Windows | T1059.001 | Medium | Validated |

## Repository Structure

- `sigma-rules/` — Sigma detection rules
- `sample-logs/` — Safe sample security events
- `detections/` — Detection outputs and test results
- `threat-hunts/` — Threat-hunting queries and notes
- `incident-reports/` — Investigation reports
- `automation/` — Python automation scripts
- `screenshots/` — Project evidence and dashboards

## Progress

- [x] Created the repository structure
- [x] Installed Sigma CLI
- [x] Created the first Sigma rule
- [x] Validated the rule with Sigma CLI
- [ ] Test the rule against sample log data
- [ ] Build Python detection automation
- [ ] Integrate Sysmon telemetry
- [ ] Integrate Wazuh
