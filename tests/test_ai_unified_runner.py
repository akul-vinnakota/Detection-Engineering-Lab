import importlib.util
from pathlib import Path


SCRIPT_PATH = Path("automation/run_all_detections.py")

spec = importlib.util.spec_from_file_location(
    "run_all_detections",
    SCRIPT_PATH,
)
runner = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(runner)


def test_load_alerts_reads_jsonl(tmp_path) -> None:
    alert_file = tmp_path / "alerts.jsonl"
    alert_file.write_text(
        '{"rule":"Test","severity":"high","event":{}}\n',
        encoding="utf-8",
    )

    detection = {
        "name": "Test",
        "alert_file": str(alert_file),
    }

    alerts = runner.load_alerts(detection)

    assert len(alerts) == 1
    assert alerts[0]["rule"] == "Test"


def test_load_alerts_wraps_text_alert(tmp_path) -> None:
    alert_file = tmp_path / "alerts.txt"
    alert_file.write_text(
        "ALERT: suspicious activity\n",
        encoding="utf-8",
    )

    detection = {
        "name": "SSH Brute Force",
        "alert_file": str(alert_file),
    }

    alerts = runner.load_alerts(detection)

    assert len(alerts) == 1
    assert alerts[0]["rule"] == "SSH Brute Force"


def test_run_ai_triage_uses_normalization_and_analysis(
    monkeypatch,
    tmp_path,
) -> None:
    alert_file = tmp_path / "alerts.jsonl"
    alert_file.write_text(
        '{"rule":"Test","severity":"high","event":{}}\n',
        encoding="utf-8",
    )

    original_detections = runner.DETECTIONS

    runner.DETECTIONS = [
        {
            "name": "Test Detection",
            "script": "unused.py",
            "alert_file": str(alert_file),
        }
    ]

    monkeypatch.setattr(
        runner,
        "analyze_alert",
        lambda alert: {
            "severity": "high",
            "confidence": 0.95,
            "attack_techniques": [],
            "analysis_summary": "Test analysis",
            "potential_false_positives": [],
            "recommended_actions": ["Investigate"],
        },
    )

    results = [
        {
            "name": "Test Detection",
            "status": "passed",
            "alerts": 1,
        }
    ]

    analyses = runner.run_ai_triage(results)

    runner.DETECTIONS = original_detections

    assert len(analyses) == 1
    assert analyses[0]["detection"] == "Test Detection"
    assert analyses[0]["ai_analysis"]["confidence"] == 0.95


def test_ai_triage_skips_failed_detection() -> None:
    results = [
        {
            "name": runner.DETECTIONS[0]["name"],
            "status": "failed",
            "alerts": 0,
        }
    ]

    assert runner.run_ai_triage(results) == []
