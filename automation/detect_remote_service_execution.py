import json
from pathlib import Path

LOG_FILE = Path("sample-logs/windows_remote_service_events.jsonl")
ALERT_FILE = Path("detections/remote_service_execution_alerts.jsonl")

SUSPICIOUS_SERVICE_NAMES = (
    "psexesvc",
    "paexec",
)

SUSPICIOUS_PATH_INDICATORS = (
    "\\admin$\\",
    "\\psexesvc.exe",
    "\\paexec.exe",
)


def is_remote_service_execution(event: dict) -> bool:
    event_id = event.get("EventID")
    service_name = str(event.get("ServiceName", "")).lower()
    image_path = str(event.get("ImagePath", "")).lower()

    suspicious_name = any(
        indicator in service_name
        for indicator in SUSPICIOUS_SERVICE_NAMES
    )

    suspicious_path = any(
        indicator in image_path
        for indicator in SUSPICIOUS_PATH_INDICATORS
    )

    return event_id == 7045 and (
        suspicious_name or suspicious_path
    )


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

            if is_remote_service_execution(event):
                alerts.append(
                    {
                        "rule": "Suspicious Remote Service Execution",
                        "severity": "high",
                        "mitre_attack": [
                            "T1021.002",
                            "T1569.002",
                        ],
                        "event": event,
                    }
                )

    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with ALERT_FILE.open("w", encoding="utf-8") as alert_file:
        for alert in alerts:
            alert_file.write(json.dumps(alert) + "\n")

    print(f"Processed log file: {LOG_FILE}")
    print(f"Remote-service alerts generated: {len(alerts)}")
    print(f"Alert output: {ALERT_FILE}")

    for alert in alerts:
        event = alert["event"]
        print(
            f"ALERT: Service {event.get('ServiceName')} created on "
            f"{event.get('Computer')} from "
            f"{event.get('SourceComputer', 'unknown source')}"
        )


if __name__ == "__main__":
    main()
