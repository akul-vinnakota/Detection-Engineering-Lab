# LLM-Assisted Alert Triage

## Workflow

1. A detection generates a security alert.
2. The alert is normalized into a consistent schema.
3. The normalized alert is converted into a structured analysis prompt.
4. Python sends the alert context to the OpenAI Responses API.
5. Structured Outputs enforce a predefined JSON response format.
6. The returned analysis contains:
   - Severity
   - Confidence
   - MITRE ATT&CK techniques
   - Analysis summary
   - Potential false positives
   - Recommended investigation actions
7. The structured output can be consumed by an analyst, report, or future SIEM integration.

## Reliability Controls

The AI workflow is designed so that:

- Missing telemetry is explicitly labeled as unknown.
- The model is instructed not to invent evidence.
- Output must follow a strict JSON schema.
- API calls are isolated from the detection engine.
- Automated tests use a mocked API client rather than consuming API credits.
- Detection logic remains deterministic even if the AI service is unavailable.

## Current Demonstration

The first live enrichment workflow analyzes an encoded PowerShell detection mapped to MITRE ATT&CK T1059.001.

The resulting AI analysis is stored as structured JSON and includes analyst-oriented triage recommendations.

## Security

API keys are supplied through environment variables and are never stored in source code or committed to the repository.
