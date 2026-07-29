import importlib.util
from pathlib import Path


SCRIPT_PATH = Path("automation/detect_scheduled_task.py")

spec = importlib.util.spec_from_file_location(
    "detect_scheduled_task",
    SCRIPT_PATH,
)
detector = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(detector)


def test_detects_suspicious_powershell_task() -> None:
    event = {
        "Image": r"C:\Windows\System32\schtasks.exe",
        "CommandLine": (
            r'schtasks.exe /create /tn "SystemTelemetry" '
            r'/tr "powershell.exe -File '
            r'C:\Users\Akul\AppData\Local\Temp\telemetry.ps1" '
            r'/sc onlogon'
        ),
    }

    assert detector.is_suspicious_scheduled_task(event) is True


def test_ignores_legitimate_scheduled_task() -> None:
    event = {
        "Image": r"C:\Windows\System32\schtasks.exe",
        "CommandLine": (
            r'schtasks.exe /create /tn "Approved Update" '
            r'/tr "C:\Program Files\Updater\update.exe" /sc daily'
        ),
    }

    assert detector.is_suspicious_scheduled_task(event) is False


def test_ignores_non_schtasks_process() -> None:
    event = {
        "Image": r"C:\Windows\System32\notepad.exe",
        "CommandLine": (
            r'notepad.exe C:\Users\Akul\AppData\Local\Temp\notes.txt'
        ),
    }

    assert detector.is_suspicious_scheduled_task(event) is False


def test_requires_task_creation_argument() -> None:
    event = {
        "Image": r"C:\Windows\System32\schtasks.exe",
        "CommandLine": "schtasks.exe /query powershell",
    }

    assert detector.is_suspicious_scheduled_task(event) is False
