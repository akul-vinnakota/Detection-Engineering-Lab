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


def test_count_alerts_counts_nonempty_lines(tmp_path) -> None:
    alert_file = tmp_path / "alerts.jsonl"
    alert_file.write_text(
        '{"alert": 1}\n\n{"alert": 2}\n',
        encoding="utf-8",
    )

    assert runner.count_alerts(alert_file) == 2


def test_count_alerts_returns_zero_for_missing_file(tmp_path) -> None:
    missing_file = tmp_path / "missing.jsonl"

    assert runner.count_alerts(missing_file) == 0


def test_markdown_summary_contains_detection_name() -> None:
    results = [
        {
            "name": "Encoded PowerShell",
            "status": "passed",
            "alerts": 1,
        }
    ]

    report = runner.build_markdown(results)

    assert "Encoded PowerShell" in report
    assert "Detections executed:** 1" in report
    assert "Total alerts generated:** 1" in report


def test_runner_tracks_eight_detections() -> None:
    assert len(runner.DETECTIONS) == 8
