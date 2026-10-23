import json

from ai.llm_client import analyze_alert


class FakeResponse:
    output_text = json.dumps(
        {
            "severity": "high",
            "confidence": 0.91,
            "attack_techniques": [
                {
                    "technique_id": "T1059.001",
                    "technique_name": "PowerShell",
                }
            ],
            "analysis_summary": (
                "Encoded PowerShell execution requires investigation."
            ),
            "potential_false_positives": [
                "Approved administrative automation"
            ],
            "recommended_actions": [
                "Review the parent process",
                "Inspect related network activity",
            ],
        }
    )


class FakeResponses:
    def create(self, **kwargs):
        return FakeResponse()


class FakeClient:
    def __init__(self):
        self.responses = FakeResponses()


def test_analyze_alert_returns_structured_analysis() -> None:
    alert = {
        "detection_name": "PowerShell Encoded Command Execution",
        "severity": "medium",
        "mitre_attack": ["T1059.001"],
        "host": "LAB-WIN10",
        "user": r"LAB-WIN10\Akul",
        "source_process": r"C:\Windows\System32\powershell.exe",
        "command_line": "powershell.exe -EncodedCommand TEST",
        "source_ip": "unknown",
        "raw_event": {},
    }

    result = analyze_alert(
        alert,
        client=FakeClient(),
    )

    assert result["severity"] == "high"
    assert result["confidence"] == 0.91
    assert result["attack_techniques"][0]["technique_id"] == "T1059.001"


def test_analyze_alert_contains_recommendations() -> None:
    result = analyze_alert(
        {
            "detection_name": "Test",
            "severity": "medium",
            "mitre_attack": [],
            "host": "LAB-WIN10",
            "user": "unknown",
            "source_process": "unknown",
            "command_line": "",
            "source_ip": "unknown",
            "raw_event": {},
        },
        client=FakeClient(),
    )

    assert len(result["recommended_actions"]) >= 1
    assert len(result["potential_false_positives"]) >= 1
