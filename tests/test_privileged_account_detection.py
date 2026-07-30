import importlib.util
from pathlib import Path


SCRIPT_PATH = Path("automation/detect_privileged_account.py")

spec = importlib.util.spec_from_file_location(
    "detect_privileged_account",
    SCRIPT_PATH,
)
detector = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(detector)


def test_detects_new_privileged_account() -> None:
    events = [
        {
            "EventID": 4720,
            "UtcTime": "2026-07-29T19:00:00Z",
            "Computer": "LAB-WIN10",
            "TargetUserName": "backupadmin",
            "TargetSid": "S-1-5-21-1000-1000-1000-1105",
        },
        {
            "EventID": 4732,
            "UtcTime": "2026-07-29T19:02:00Z",
            "Computer": "LAB-WIN10",
            "TargetUserName": "Administrators",
            "MemberName": "backupadmin",
            "MemberSid": "S-1-5-21-1000-1000-1000-1105",
        },
    ]

    alerts = detector.correlate_privileged_accounts(events)

    assert len(alerts) == 1
    assert alerts[0]["account"] == "backupadmin"
    assert alerts[0]["correlation_window_seconds"] == 120


def test_ignores_account_not_added_to_administrators() -> None:
    events = [
        {
            "EventID": 4720,
            "UtcTime": "2026-07-29T19:00:00Z",
            "Computer": "LAB-WIN10",
            "TargetUserName": "testuser",
            "TargetSid": "S-1-5-21-1000-1000-1000-1106",
        }
    ]

    assert detector.correlate_privileged_accounts(events) == []


def test_ignores_group_addition_outside_window() -> None:
    events = [
        {
            "EventID": 4720,
            "UtcTime": "2026-07-29T19:00:00Z",
            "Computer": "LAB-WIN10",
            "TargetUserName": "lateadmin",
            "TargetSid": "S-1-5-21-1000-1000-1000-1107",
        },
        {
            "EventID": 4732,
            "UtcTime": "2026-07-29T19:10:00Z",
            "Computer": "LAB-WIN10",
            "TargetUserName": "Administrators",
            "MemberName": "lateadmin",
            "MemberSid": "S-1-5-21-1000-1000-1000-1107",
        },
    ]

    assert detector.correlate_privileged_accounts(events) == []


def test_ignores_different_account_sid() -> None:
    events = [
        {
            "EventID": 4720,
            "UtcTime": "2026-07-29T19:00:00Z",
            "Computer": "LAB-WIN10",
            "TargetUserName": "userone",
            "TargetSid": "S-1-5-21-1000-1000-1000-1108",
        },
        {
            "EventID": 4732,
            "UtcTime": "2026-07-29T19:01:00Z",
            "Computer": "LAB-WIN10",
            "TargetUserName": "Administrators",
            "MemberName": "usertwo",
            "MemberSid": "S-1-5-21-1000-1000-1000-1109",
        },
    ]

    assert detector.correlate_privileged_accounts(events) == []
