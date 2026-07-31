import json
from pathlib import Path

LOG_FILE = Path("sample-logs/windows_defender_events.jsonl")
ALERT_FILE = Path("detections/defender_exclusion_alerts.jsonl")

DEFENDER_COMMANDS = (
    "add-mppreference",
    "set-mppreference",
)

EXCLUSION_ARGUMENTS = (
    "-exclusionpath",
    "-exclusionprocess",
    "-exclusionextension",
    "-exclusionipaddress",
)


def is_defender_exclusion_change(event: dict) -> bool:
    image = str(event.get("Image", "")).lower()
    command_line = str(event.get("CommandLine", "")).lower()

    is_powershell = image.endswith(
        ("\\powershell.exe", "\\pwsh.exe")
    )
    modifies_defender = any(
        command in command_line
        for command in DEFENDER_COMMANDS
    )
    adds_exclusion = any(
        argument in command_line
        for argument in EXCLUSION_ARGUMENTS
    )

    return is_powershell and modifies_defender and adds_exclusion


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

            if is_defender_exclusion_change(event):
                alerts.append(
                    {
                        "rule": (
                            "Microsoft Defender Exclusion Added "
                            "Through PowerShell"
                        ),
                        "severity": "high",
                        "mitre_attack": "T1685",
                        "event": event,
                    }
                )

    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with ALERT_FILE.open("w", encoding="utf-8") as alert_file:
        for alert in alerts:
            alert_file.write(json.dumps(alert) + "\n")

    print(f"Processed log file: {LOG_FILE}")
    print(f"Defender exclusion alerts generated: {len(alerts)}")
    print(f"Alert output: {ALERT_FILE}")


if __name__ == "__main__":
    main()
