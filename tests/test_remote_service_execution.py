import importlib.util
from pathlib import Path


SCRIPT_PATH = Path("automation/detect_remote_service_execution.py")

spec = importlib.util.spec_from_file_location(
    "detect_remote_service_execution",
    SCRIPT_PATH,
)
detector = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(detector)


def test_detects_psexec_service_name() -> None:
    event = {
        "EventID": 7045,
        "ServiceName": "PSEXESVC",
        "ImagePath": r"C:\Windows\PSEXESVC.exe",
    }

    assert detector.is_remote_service_execution(event) is True


def test_detects_paexec_image_path() -> None:
    event = {
        "EventID": 7045,
        "ServiceName": "RemoteUpdater",
        "ImagePath": r"C:\Windows\PAExec.exe",
    }

    assert detector.is_remote_service_execution(event) is True


def test_ignores_legitimate_service() -> None:
    event = {
        "EventID": 7045,
        "ServiceName": "BackupAgent",
        "ImagePath": r"C:\Program Files\BackupAgent\backup.exe",
    }

    assert detector.is_remote_service_execution(event) is False


def test_requires_service_creation_event() -> None:
    event = {
        "EventID": 7036,
        "ServiceName": "PSEXESVC",
        "ImagePath": r"C:\Windows\PSEXESVC.exe",
    }

    assert detector.is_remote_service_execution(event) is False
