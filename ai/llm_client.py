import json
import os
from typing import Any

from openai import OpenAI

from ai.prompt_builder import build_analysis_prompt


MODEL = os.getenv("OPENAI_MODEL", "gpt-5-mini")

ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "severity": {
            "type": "string",
            "enum": ["low", "medium", "high", "critical"],
        },
        "confidence": {
            "type": "number",
            "minimum": 0,
            "maximum": 1,
        },
        "attack_techniques": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technique_id": {"type": "string"},
                    "technique_name": {"type": "string"},
                },
                "required": [
                    "technique_id",
                    "technique_name",
                ],
                "additionalProperties": False,
            },
        },
        "analysis_summary": {
            "type": "string",
        },
        "potential_false_positives": {
            "type": "array",
            "items": {"type": "string"},
        },
        "recommended_actions": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": [
        "severity",
        "confidence",
        "attack_techniques",
        "analysis_summary",
        "potential_false_positives",
        "recommended_actions",
    ],
    "additionalProperties": False,
}


def analyze_alert(
    alert: dict[str, Any],
    client: OpenAI | None = None,
) -> dict[str, Any]:
    if client is None:
        if not os.getenv("OPENAI_API_KEY"):
            raise RuntimeError(
                "OPENAI_API_KEY is not configured."
            )

        client = OpenAI()

    response = client.responses.create(
        model=MODEL,
        input=build_analysis_prompt(alert),
        text={
            "format": {
                "type": "json_schema",
                "name": "security_alert_analysis",
                "schema": ANALYSIS_SCHEMA,
                "strict": True,
            }
        },
    )

    if not response.output_text:
        raise RuntimeError(
            "LLM returned no structured analysis."
        )

    return json.loads(response.output_text)
