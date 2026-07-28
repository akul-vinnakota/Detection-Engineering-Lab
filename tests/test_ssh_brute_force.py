import importlib.util
from pathlib import Path


SCRIPT_PATH = Path("automation/detect_ssh_brute_force.py")

spec = importlib.util.spec_from_file_location(
    "detect_ssh_brute_force",
    SCRIPT_PATH,
)
detector = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(detector)


def test_extracts_failed_login_ip() -> None:
    log_line = (
        "Jul 27 18:03:10 ubuntu sshd[2110]: "
        "Failed password for invalid user admin "
        "from 203.0.113.50 port 52001 ssh2"
    )

    assert detector.extract_failed_login_ip(log_line) == "203.0.113.50"


def test_detects_five_failed_attempts() -> None:
    logs = [
        f"Failed password for root from 203.0.113.50 port {port} ssh2"
        for port in range(52001, 52006)
    ]

    assert detector.detect_brute_force(logs) == {
        "203.0.113.50": 5,
    }


def test_ignores_attempts_below_threshold() -> None:
    logs = [
        f"Failed password for root from 198.51.100.20 port {port} ssh2"
        for port in range(53001, 53005)
    ]

    assert detector.detect_brute_force(logs) == {}


def test_ignores_successful_login() -> None:
    logs = [
        "Accepted password for akul from 10.0.0.25 port 51001 ssh2",
    ]

    assert detector.detect_brute_force(logs) == {}
