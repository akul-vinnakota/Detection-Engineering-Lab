# AI-Enabled Unified Detection Runner

## Purpose

The unified runner executes the full detection library and can optionally send triggered alerts through the AI-assisted triage workflow.

## Default Mode

Run `python3 automation/run_all_detections.py` to execute all detections without API calls.

## AI Mode

Run `python3 automation/run_all_detections.py --ai` to enable AI-assisted triage.

Each alert is loaded, normalized, sent to the LLM analysis layer, returned as structured JSON, and written to `detections/ai_triage_summary.json`.

## API Cost Control

Use `--ai-limit 1` to limit the number of alerts sent to the LLM during testing.

## AI Output

- Severity
- Confidence
- MITRE ATT&CK mapping
- Analysis summary
- Potential false positives
- Recommended investigation actions

## Design Principle

The deterministic detection engine remains independent from the optional AI enrichment layer.
