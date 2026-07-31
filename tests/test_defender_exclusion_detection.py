import importlib.util
from pathlib import Path


SCRIPT_PATH = Path("automation/detect_defender_exclusion.py")

spec = importlib.util.spec_from_file_location(
    "detect_defender_exclusion",
    SCRIPT_PATH,
)
detector = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(detector)


def test_detects_defender_path_exclusion() -> None:
    event = {
        "Image": (
            r"C:\Windows\System32\WindowsPowerShell\v1.0"
            r"\powershell.exe"
        ),
        "CommandLine": (
            r"powershell.exe Add-MpPreference "
            r"-ExclusionPath C:\Users\Public\Downloads"
        ),
    }

    assert detector.is_defender_exclusion_change(event) is True


def test_detects_defender_process_exclusion() -> None:
    event = {
        "Image": r"C:\Program Files\PowerShell\7\pwsh.exe",
        "CommandLine": (
            r"pwsh.exe Set-MpPreference "
            r"-ExclusionProcess suspicious.exe"
        ),
    }

    assert detector.is_defender_exclusion_change(event) is True


def test_ignores_normal_defender_command() -> None:
    event = {
        "Image": (
            r"C:\Windows\System32\WindowsPowerShell\v1.0"
            r"\powershell.exe"
        ),
        "CommandLine": "powershell.exe Get-MpComputerStatus",
    }

    assert detector.is_defender_exclusion_change(event) is False


def test_ignores_non_powershell_process() -> None:
    event = {
        "Image": r"C:\Windows\System32\cmd.exe",
        "CommandLine": (
            r"cmd.exe Add-MpPreference "
            r"-ExclusionPath C:\Temp"
        ),
    }

    assert detector.is_defender_exclusion_change(event) is False
