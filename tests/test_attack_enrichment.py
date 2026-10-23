from ai.attack_enrichment import enrich_attack_techniques
from ai.enrichment_schema import normalize_alert


def test_valid_attack_technique_is_enriched() -> None:
    result = enrich_attack_techniques(["T1059.001"])

    assert result["unknown"] == []
    assert len(result["validated"]) == 1
    assert result["validated"][0]["technique_id"] == "T1059.001"
    assert result["validated"][0]["technique_name"] == "PowerShell"


def test_unknown_attack_technique_is_rejected() -> None:
    result = enrich_attack_techniques(["T9999.999"])

    assert result["validated"] == []
    assert result["unknown"] == ["T9999.999"]


def test_mixed_attack_techniques_are_separated() -> None:
    result = enrich_attack_techniques(
        [
            "T1003.001",
            "T9999.999",
        ]
    )

    assert len(result["validated"]) == 1
    assert result["validated"][0]["technique_id"] == "T1003.001"
    assert result["unknown"] == ["T9999.999"]


def test_normalized_alert_contains_grounded_attack_context() -> None:
    alert = {
        "rule": "Suspicious LSASS Access",
        "severity": "high",
        "mitre_attack": "T1003.001",
        "event": {
            "Computer": "LAB-WIN10",
            "SourceImage": r"C:\Temp\diagnostic.exe",
        },
    }

    result = normalize_alert(alert)

    assert "attack_context" in result
    assert result["attack_context"]["unknown"] == []
    assert (
        result["attack_context"]["validated"][0]["technique_name"]
        == "LSASS Memory"
    )


def test_normalized_alert_preserves_unknown_attack_id() -> None:
    alert = {
        "rule": "Test Detection",
        "severity": "medium",
        "mitre_attack": "T9999.999",
        "event": {},
    }

    result = normalize_alert(alert)

    assert result["mitre_attack"] == ["T9999.999"]
    assert result["attack_context"]["validated"] == []
    assert result["attack_context"]["unknown"] == ["T9999.999"]
