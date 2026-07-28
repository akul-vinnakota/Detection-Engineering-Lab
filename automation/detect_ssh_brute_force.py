import re
from collections import Counter
from pathlib import Path

LOG_FILE = Path("sample-logs/linux_auth.log")
ALERT_FILE = Path("detections/ssh_brute_force_alerts.txt")
FAILURE_THRESHOLD = 5

FAILED_LOGIN_PATTERN = re.compile(
    r"Failed password.* from (?P<source_ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def extract_failed_login_ip(log_line: str) -> str | None:
    match = FAILED_LOGIN_PATTERN.search(log_line)

    if match is None:
        return None

    return match.group("source_ip")


def detect_brute_force(log_lines: list[str]) -> dict[str, int]:
    failed_attempts = Counter()

    for log_line in log_lines:
        source_ip = extract_failed_login_ip(log_line)

        if source_ip:
            failed_attempts[source_ip] += 1

    return {
        source_ip: count
        for source_ip, count in failed_attempts.items()
        if count >= FAILURE_THRESHOLD
    }


def main() -> None:
    if not LOG_FILE.exists():
        raise FileNotFoundError(f"Log file not found: {LOG_FILE}")

    log_lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
    alerts = detect_brute_force(log_lines)

    ALERT_FILE.parent.mkdir(parents=True, exist_ok=True)

    output_lines = []

    for source_ip, attempt_count in alerts.items():
        output_lines.append(
            f"ALERT: Possible SSH brute force from {source_ip} "
            f"with {attempt_count} failed login attempts | "
            f"MITRE ATT&CK: T1110.001 | Severity: Medium"
        )

    ALERT_FILE.write_text(
        "\n".join(output_lines) + ("\n" if output_lines else ""),
        encoding="utf-8",
    )

    print(f"Processed log file: {LOG_FILE}")
    print(f"Brute-force alerts generated: {len(alerts)}")
    print(f"Alert output: {ALERT_FILE}")

    for alert in output_lines:
        print(alert)


if __name__ == "__main__":
    main()
