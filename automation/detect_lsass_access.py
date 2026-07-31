import json
from pathlib import Path

LOG_FILE = Path("sample-logs/windows_lsass_access_events.jsonl")
ALERT_FILE = Path("detections/lsass_access_alerts.jsonl")

SUSPICIOUS_ACCESS_RIGHTS = {
    "0x1f0fff",
    "0x1fffff",
    "0x1010",
    "0x1410",
    "0x1438",
    "0x143a",
}


def is_suspicious_lsass_access(event: dict) -> bool:
    event_id = event.get("EventID")
    target_image = str(event.get("TargetImage", "")).lower()
    granted_access = str(event.get("GrantedAccess", "")).lower()

    targets_lsass = target_image.endswith("\\lsass.exe")
    requests_suspicious_access = (
        granted_access in SUSPICIOUS_ACCESS_RIGHTS
    )

    return (
        event_id == 10
        and targets_lsass
        and requests_suspicious_access
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

            if is_suspicious_lsass_access(event):
                alerts.append(
                    {
                        "rule": "Suspicious Process Access to LSASS",
                        "severity": "high",
                        "mitre_attack": "T1003.001",
                        "event": event,
                    }
                )

    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with ALERT_FILE.open("w", encoding="utf-8") as alert_file:
        for alert in alerts:
            alert_file.write(json.dumps(alert) + "\n")

    print(f"Processed log file: {LOG_FILE}")
    print(f"LSASS access alerts generated: {len(alerts)}")
    print(f"Alert output: {ALERT_FILE}")

    for alert in alerts:
        event = alert["event"]
        print(
            f"ALERT: {event.get('SourceImage')} accessed "
            f"{event.get('TargetImage')} with "
            f"{event.get('GrantedAccess')}"
        )


if __name__ == "__main__":
    main()
