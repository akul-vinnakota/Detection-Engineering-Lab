import json
from typing import Any


SYSTEM_INSTRUCTIONS = """You are assisting a security analyst with alert triage.

Analyze only the evidence provided.

Return:
- severity
- confidence
- MITRE ATT&CK techniques
- concise explanation
- potential false positives
- recommended investigation actions

Do not invent missing telemetry.
Clearly identify uncertainty when evidence is incomplete.
"""


def build_analysis_prompt(alert: dict[str, Any]) -> str:
    alert_json = json.dumps(
        alert,
        indent=2,
        sort_keys=True,
    )

    return f"""{SYSTEM_INSTRUCTIONS}

SECURITY ALERT:

{alert_json}
"""


def build_expected_output_schema() -> dict[str, Any]:
    return {
        "severity": "low | medium | high | critical",
        "confidence": 0.0,
        "attack_techniques": [
            {
                "technique_id": "TXXXX.XXX",
                "technique_name": "Technique Name",
            }
        ],
        "analysis_summary": "Short evidence-based explanation",
        "potential_false_positives": [
            "Possible legitimate explanation"
        ],
        "recommended_actions": [
            "Investigation action"
        ],
    }
