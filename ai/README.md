# AI Alert Enrichment Layer

## Purpose

The AI enrichment layer prepares detection alerts for structured LLM-assisted security analysis.

## Current Workflow

1. A Sigma/Python detection generates an alert.
2. The alert is normalized into a consistent schema.
3. Missing telemetry is explicitly marked as unknown.
4. The normalized alert is converted into an LLM-ready security-analysis prompt.
5. The expected output format defines structured fields for triage and investigation.

## Normalized Fields

- Detection name
- Severity
- MITRE ATT&CK techniques
- Host
- User
- Source process
- Command line
- Source IP
- Raw event telemetry

## Expected AI Output

Future LLM analysis will return:

- Severity
- Confidence
- MITRE ATT&CK mapping
- Evidence-based analysis summary
- Potential false positives
- Recommended investigation actions

## Safety and Reliability

The prompt instructs the model to:

- Analyze only provided telemetry
- Avoid inventing missing evidence
- Identify uncertainty
- Produce structured analyst recommendations

## Status

The enrichment and prompt-building foundation is complete.

The OpenAI API integration will be added in the next phase.
