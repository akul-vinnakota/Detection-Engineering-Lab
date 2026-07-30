import json
from datetime import datetime, timezone
from pathlib import Path

LOG_FILE = Path("sample-logs/windows_account_events.jsonl")
ALERT_FILE = Path("detections/privileged_account_alerts.jsonl")
CORRELATION_WINDOW_SECONDS = 300


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
        timezone.utc
    )


def correlate_privileged_accounts(events: list[dict]) -> list[dict]:
    created_accounts: dict[tuple[str, str], dict] = {}
    alerts = []

    sorted_events = sorted(
        events,
        key=lambda event: parse_timestamp(event["UtcTime"]),
    )

    for event in sorted_events:
        event_id = event.get("EventID")
        computer = str(event.get("Computer", ""))

        if event_id == 4720:
            username = str(event.get("TargetUserName", ""))
            account_sid = str(event.get("TargetSid", ""))
            key = (computer, account_sid or username)

            created_accounts[key] = event

        elif (
            event_id == 4732
            and str(event.get("TargetUserName", "")).lower()
            == "administrators"
        ):
            username = str(event.get("MemberName", ""))
            account_sid = str(event.get("MemberSid", ""))
            key = (computer, account_sid or username)
            creation_event = created_accounts.get(key)

            if creation_event is None:
                continue

            creation_time = parse_timestamp(creation_event["UtcTime"])
            privilege_time = parse_timestamp(event["UtcTime"])
            elapsed_seconds = (
                privilege_time - creation_time
            ).total_seconds()

            if 0 <= elapsed_seconds <= CORRELATION_WINDOW_SECONDS:
                alerts.append(
                    {
                        "rule": (
                            "New Account Added to Local Administrators Group"
                        ),
                        "severity": "high",
                        "mitre_attack": [
                            "T1136.001",
                            "T1098.007",
                        ],
                        "computer": computer,
                        "account": username,
                        "account_sid": account_sid,
                        "correlation_window_seconds": elapsed_seconds,
                        "account_creation_event": creation_event,
                        "group_addition_event": event,
                    }
                )

    return alerts


def main() -> None:
    if not LOG_FILE.exists():
        raise FileNotFoundError(f"Log file not found: {LOG_FILE}")

    events = []

    with LOG_FILE.open("r", encoding="utf-8") as log_file:
        for line_number, line in enumerate(log_file, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                events.append(json.loads(line))
            except json.JSONDecodeError as error:
                print(f"Skipping invalid JSON on line {line_number}: {error}")

    alerts = correlate_privileged_accounts(events)

    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with ALERT_FILE.open("w", encoding="utf-8") as alert_file:
        for alert in alerts:
            alert_file.write(json.dumps(alert) + "\n")

    print(f"Processed events: {len(events)}")
    print(f"Privileged-account alerts generated: {len(alerts)}")
    print(f"Alert output: {ALERT_FILE}")

    for alert in alerts:
        print(
            f"ALERT: Account {alert['account']} was created and added "
            f"to Administrators within "
            f"{int(alert['correlation_window_seconds'])} seconds"
        )


if __name__ == "__main__":
    main()
