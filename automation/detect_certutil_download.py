import json
from pathlib import Path

LOG_FILE = Path("sample-logs/windows_certutil_events.jsonl")
ALERT_FILE = Path("detections/certutil_download_alerts.jsonl")

DOWNLOAD_ARGUMENTS = (
    "-urlcache",
    "-split",
    "-f",
)


def is_suspicious_certutil_download(event: dict) -> bool:
    image = str(event.get("Image", "")).lower()
    command_line = str(event.get("CommandLine", "")).lower()

    is_certutil = image.endswith("\\certutil.exe")
    has_url = "http://" in command_line or "https://" in command_line
    has_download_argument = any(
        argument in command_line
        for argument in DOWNLOAD_ARGUMENTS
    )

    return is_certutil and has_url and has_download_argument


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

            if is_suspicious_certutil_download(event):
                alerts.append(
                    {
                        "rule": "Certutil Used to Download File",
                        "severity": "high",
                        "mitre_attack": "T1105",
                        "event": event,
                    }
                )

    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with ALERT_FILE.open("w", encoding="utf-8") as alert_file:
        for alert in alerts:
            alert_file.write(json.dumps(alert) + "\n")

    print(f"Processed log file: {LOG_FILE}")
    print(f"Certutil alerts generated: {len(alerts)}")
    print(f"Alert output: {ALERT_FILE}")


if __name__ == "__main__":
    main()
