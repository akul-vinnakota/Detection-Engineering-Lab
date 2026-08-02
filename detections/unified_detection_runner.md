# Unified Detection Runner

## Purpose

The unified detection runner executes every detection script in the lab from one command and produces a consolidated summary of detection status and alert counts.

## Current Coverage

The runner executes eight detections:

1. Encoded PowerShell
2. SSH Brute Force
3. Scheduled Task Persistence
4. Privileged Account Correlation
5. Defender Exclusion Tampering
6. Suspicious LSASS Access
7. Remote Service Execution
8. Certutil Download

## Outputs

The runner generates:

- `detections/detection_summary.json`
- `detections/detection_summary.md`

These reports show whether each detector executed successfully and how many alerts were generated.

## Why This Matters

Instead of manually executing each detection script, the lab now has one centralized entry point.

This improves:

- Repeatability
- Detection validation
- Alert visibility
- Automation
- Scalability as new detections are added
