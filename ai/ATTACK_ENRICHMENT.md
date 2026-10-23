# Grounded MITRE ATT&CK Enrichment

## Purpose

This layer validates MITRE ATT&CK technique IDs before they are used in AI-assisted triage.

## Workflow

1. A detection produces one or more ATT&CK technique IDs.
2. Python checks those IDs against the local ATT&CK catalog.
3. Valid techniques are enriched with technique names and tactics.
4. Unknown technique IDs are separated and flagged.
5. Grounded ATT&CK context is included in the normalized alert sent to the LLM.
6. ATT&CK IDs returned by the LLM are validated again before analyst output.

## Reliability Benefit

The LLM is not treated as the source of truth for ATT&CK mappings. Deterministic validation helps prevent hallucinated or invalid technique IDs from silently entering analyst reports.
