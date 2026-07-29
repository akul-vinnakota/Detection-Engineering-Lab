import json
from pathlib import Path

LOG_FILE = Path("sample-logs/windows_scheduled_task_events.jsonl")
ALERT_FILE = Path("detections/scheduled_task_alerts.jsonl")

SUSPICIOUS_INDICATORS = (
    "powershell",
    "cmd.exe",
    "\\appdata\\",
    "\\temp\\",
    "http://",
    "https://",
)


def is_suspicious_scheduled_task(event: dict) -> bool:
    image = str(event.get("Image", "")).lower()
    command_line = str(event.get("CommandLine", "")).lower()

    is_schtasks = image.endswith("\\schtasks.exe")
    creates_task = "/create" in command_line or "-create" in command_line
    has_suspicious_content = any(
        indicator in command_line
        for indicator in SUSPICIOUS_INDICATORS
    )

    return is_schtasks and creates_task and has_suspicious_content


def main() -> None:
    if not LOG_FILE.exists():
        raise FileNotFoundError(f"Log file not found: {LOG_FILE}")

    alerts = []

    with LOG_FILE.open("r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                print(f"Skipping invalid JSON on line {line_number}: {error}")
                continue

            if is_suspicious_scheduled_task(event):
                alerts.append(
                    {
                        "rule": "Suspicious Windows Scheduled Task Creation",
                        "severity": "high",
                        "mitre_attack": "T1053.005",
                        "event": event,
                    }
                )

    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with ALERT_FILE.open("w", encoding="utf-8") as alert_file:
        for alert in alerts:
            alert_file.write(json.dumps(alert) + "\n")

    print(f"Processed log file: {LOG_FILE}")
    print(f"Scheduled-task alerts generated: {len(alerts)}")
    print(f"Alert output: {ALERT_FILE}")


if __name__ == "__main__":
    main()
