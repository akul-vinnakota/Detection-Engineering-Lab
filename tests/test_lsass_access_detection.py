import importlib.util
from pathlib import Path


SCRIPT_PATH = Path("automation/detect_lsass_access.py")

spec = importlib.util.spec_from_file_location(
    "detect_lsass_access",
    SCRIPT_PATH,
)
detector = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(detector)


def test_detects_suspicious_lsass_access() -> None:
    event = {
        "EventID": 10,
        "SourceImage": r"C:\Users\Akul\Downloads\diagnostic.exe",
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1010",
    }

    assert detector.is_suspicious_lsass_access(event) is True


def test_ignores_low_access_to_lsass() -> None:
    event = {
        "EventID": 10,
        "SourceImage": r"C:\Windows\System32\svchost.exe",
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1000",
    }

    assert detector.is_suspicious_lsass_access(event) is False


def test_ignores_suspicious_access_to_other_process() -> None:
    event = {
        "EventID": 10,
        "SourceImage": r"C:\Windows\System32\taskmgr.exe",
        "TargetImage": r"C:\Windows\System32\notepad.exe",
        "GrantedAccess": "0x1010",
    }

    assert detector.is_suspicious_lsass_access(event) is False


def test_requires_sysmon_event_id_10() -> None:
    event = {
        "EventID": 1,
        "SourceImage": r"C:\Users\Akul\Downloads\diagnostic.exe",
        "TargetImage": r"C:\Windows\System32\lsass.exe",
        "GrantedAccess": "0x1010",
    }

    assert detector.is_suspicious_lsass_access(event) is False
