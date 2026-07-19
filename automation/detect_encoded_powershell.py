import json
from pathlib import Path

LOG_FILE = Path("sample-logs/windows_process_events.jsonl")
ALERT_FILE = Path("detections/powershell_encoded_command_alerts.jsonl")

POWERSHELL_IMAGES = (
    "\\powershell.exe",
    "\\pwsh.exe",
)

ENCODED_ARGUMENTS = (
    " -enc ",
    " -encodedcommand ",
    " -e ",
)


def is_encoded_powershell(event: dict) -> bool:
    image = str(event.get("Image", "")).lower()
    command_line = f" {event.get('CommandLine', '')} ".lower()

    is_powershell = image.endswith(POWERSHELL_IMAGES)
    uses_encoding = any(argument in command_line for argument in ENCODED_ARGUMENTS)

    return is_powershell and uses_encoding


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

            if is_encoded_powershell(event):
                alerts.append(
                    {
                        "rule": "PowerShell Encoded Command Execution",
                        "severity": "medium",
                        "mitre_attack": "T1059.001",
                        "event": event,
                    }
                )

    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with ALERT_FILE.open("w", encoding="utf-8") as alert_file:
        for alert in alerts:
            alert_file.write(json.dumps(alert) + "\n")

    print(f"Processed log file: {LOG_FILE}")
    print(f"Alerts generated: {len(alerts)}")
    print(f"Alert output: {ALERT_FILE}")


if __name__ == "__main__":
    main()
