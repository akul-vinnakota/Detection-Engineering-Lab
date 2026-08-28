from ai.enrichment_schema import normalize_alert
from ai.prompt_builder import (
    build_analysis_prompt,
    build_expected_output_schema,
)


def test_normalizes_single_mitre_technique() -> None:
    alert = {
        "rule": "PowerShell Encoded Command Execution",
        "severity": "medium",
        "mitre_attack": "T1059.001",
        "event": {
            "Computer": "LAB-WIN10",
            "User": r"LAB-WIN10\Akul",
            "Image": r"C:\Windows\System32\powershell.exe",
            "CommandLine": "powershell.exe -EncodedCommand TEST",
        },
    }

    result = normalize_alert(alert)

    assert result["detection_name"] == (
        "PowerShell Encoded Command Execution"
    )
    assert result["mitre_attack"] == ["T1059.001"]
    assert result["host"] == "LAB-WIN10"


def test_normalizes_multiple_mitre_techniques() -> None:
    alert = {
        "rule": "Remote Service Execution",
        "severity": "high",
        "mitre_attack": [
            "T1021.002",
            "T1569.002",
        ],
        "event": {
            "Computer": "LAB-SERVER01",
        },
    }

    result = normalize_alert(alert)

    assert result["mitre_attack"] == [
        "T1021.002",
        "T1569.002",
    ]


def test_missing_telemetry_uses_unknown() -> None:
    result = normalize_alert(
        {
            "rule": "Test Detection",
            "severity": "low",
        }
    )

    assert result["host"] == "unknown"
    assert result["user"] == "unknown"
    assert result["source_process"] == "unknown"
    assert result["source_ip"] == "unknown"


def test_prompt_contains_detection_context() -> None:
    alert = normalize_alert(
        {
            "rule": "Suspicious LSASS Access",
            "severity": "high",
            "mitre_attack": "T1003.001",
            "event": {
                "Computer": "LAB-WIN10",
                "SourceImage": r"C:\Temp\diagnostic.exe",
            },
        }
    )

    prompt = build_analysis_prompt(alert)

    assert "Suspicious LSASS Access" in prompt
    assert "T1003.001" in prompt
    assert "LAB-WIN10" in prompt
    assert "Do not invent missing telemetry" in prompt


def test_expected_output_schema_contains_required_fields() -> None:
    schema = build_expected_output_schema()

    assert "severity" in schema
    assert "confidence" in schema
    assert "attack_techniques" in schema
    assert "analysis_summary" in schema
    assert "potential_false_positives" in schema
    assert "recommended_actions" in schema
