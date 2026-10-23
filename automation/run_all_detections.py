import argparse
import json
import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from ai.enrichment_schema import normalize_alert
from ai.llm_client import analyze_alert

REPORT_JSON = Path("detections/detection_summary.json")
REPORT_MD = Path("detections/detection_summary.md")

DETECTIONS = [
    {
        "name": "Encoded PowerShell",
        "script": "automation/detect_encoded_powershell.py",
        "alert_file": "detections/powershell_encoded_command_alerts.jsonl",
    },
    {
        "name": "SSH Brute Force",
        "script": "automation/detect_ssh_brute_force.py",
        "alert_file": "detections/ssh_brute_force_alerts.txt",
    },
    {
        "name": "Scheduled Task Persistence",
        "script": "automation/detect_scheduled_task.py",
        "alert_file": "detections/scheduled_task_alerts.jsonl",
    },
    {
        "name": "Privileged Account Correlation",
        "script": "automation/detect_privileged_account.py",
        "alert_file": "detections/privileged_account_alerts.jsonl",
    },
    {
        "name": "Defender Exclusion Tampering",
        "script": "automation/detect_defender_exclusion.py",
        "alert_file": "detections/defender_exclusion_alerts.jsonl",
    },
    {
        "name": "Suspicious LSASS Access",
        "script": "automation/detect_lsass_access.py",
        "alert_file": "detections/lsass_access_alerts.jsonl",
    },
    {
        "name": "Remote Service Execution",
        "script": "automation/detect_remote_service_execution.py",
        "alert_file": "detections/remote_service_execution_alerts.jsonl",
    },
    {
        "name": "Certutil Download",
        "script": "automation/detect_certutil_download.py",
        "alert_file": "detections/certutil_download_alerts.jsonl",
    },
]


def count_alerts(path: Path) -> int:
    if not path.exists():
        return 0

    return len(
        [
            line
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
    )


def run_detection(detection: dict) -> dict:
    script_path = Path(detection["script"])

    result = subprocess.run(
        [sys.executable, str(script_path)],
        capture_output=True,
        text=True,
        check=False,
    )

    alert_count = count_alerts(Path(detection["alert_file"]))

    return {
        "name": detection["name"],
        "script": detection["script"],
        "alert_file": detection["alert_file"],
        "status": "passed" if result.returncode == 0 else "failed",
        "alerts": alert_count,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }



def load_alerts(detection: dict) -> list[dict]:
    path = Path(detection["alert_file"])

    if not path.exists():
        return []

    alerts = []

    if path.suffix == ".jsonl":
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                alerts.append(json.loads(line))

    else:
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                alerts.append(
                    {
                        "rule": detection["name"],
                        "severity": "medium",
                        "mitre_attack": [],
                        "event": {
                            "message": line,
                        },
                    }
                )

    return alerts


def run_ai_triage(
    results: list[dict],
    limit: int | None = None,
) -> list[dict]:
    analyses = []

    for result in results:
        if result["status"] != "passed":
            continue

        detection = next(
            item
            for item in DETECTIONS
            if item["name"] == result["name"]
        )

        for alert in load_alerts(detection):
            normalized = normalize_alert(alert)
            analysis = analyze_alert(normalized)

            analyses.append(
                {
                    "detection": result["name"],
                    "normalized_alert": normalized,
                    "ai_analysis": analysis,
                }
            )

            if limit is not None and len(analyses) >= limit:
                return analyses

    return analyses

def build_markdown(results: list[dict]) -> str:
    total_alerts = sum(result["alerts"] for result in results)
    passed = sum(result["status"] == "passed" for result in results)

    lines = [
        "# Detection Engineering Lab Summary",
        "",
        f"- **Detections executed:** {len(results)}",
        f"- **Successful detections:** {passed}",
        f"- **Total alerts generated:** {total_alerts}",
        "",
        "| Detection | Status | Alerts |",
        "|---|---|---:|",
    ]

    for result in results:
        lines.append(
            f"| {result['name']} | {result['status']} | "
            f"{result['alerts']} |"
        )

    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ai",
        action="store_true",
        help="Run AI-assisted triage on generated alerts.",
    )
    parser.add_argument(
        "--ai-limit",
        type=int,
        default=None,
        help="Maximum number of alerts to send for AI triage.",
    )
    args = parser.parse_args()

    results = []

    print("=== Detection Engineering Lab ===")

    for detection in DETECTIONS:
        print(f"\nRunning: {detection['name']}")
        result = run_detection(detection)
        results.append(result)

        print(
            f"Status: {result['status']} | "
            f"Alerts: {result['alerts']}"
        )

    REPORT_JSON.write_text(
        json.dumps(results, indent=2) + "\n",
        encoding="utf-8",
    )

    REPORT_MD.write_text(
        build_markdown(results),
        encoding="utf-8",
    )

    total_alerts = sum(result["alerts"] for result in results)

    print("\n=== Summary ===")
    print(f"Detections executed: {len(results)}")
    print(f"Total alerts generated: {total_alerts}")
    print(f"JSON report: {REPORT_JSON}")
    print(f"Markdown report: {REPORT_MD}")

    if args.ai:
        print("\n=== AI-Assisted Triage ===")

        analyses = run_ai_triage(results, limit=args.ai_limit)

        ai_report = Path("detections/ai_triage_summary.json")
        ai_report.write_text(
            json.dumps(analyses, indent=2) + "\n",
            encoding="utf-8",
        )

        print(f"Alerts analyzed by AI: {len(analyses)}")
        print(f"AI report: {ai_report}")
    else:
        print("\nAI triage skipped. Use --ai to enable it.")


if __name__ == "__main__":
    main()
