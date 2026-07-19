import importlib.util
from pathlib import Path


SCRIPT_PATH = Path("automation/detect_encoded_powershell.py")

spec = importlib.util.spec_from_file_location(
    "detect_encoded_powershell",
    SCRIPT_PATH,
)
detector = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(detector)


def test_detects_encoded_powershell() -> None:
    event = {
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": (
            "powershell.exe -EncodedCommand "
            "VwByAGkAdABlAC0ASABvAHMAdAA="
        ),
    }

    assert detector.is_encoded_powershell(event) is True


def test_ignores_normal_powershell() -> None:
    event = {
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "CommandLine": "powershell.exe Get-Process",
    }

    assert detector.is_encoded_powershell(event) is False


def test_ignores_non_powershell_process() -> None:
    event = {
        "Image": r"C:\Windows\System32\cmd.exe",
        "CommandLine": "cmd.exe -enc harmless-value",
    }

    assert detector.is_encoded_powershell(event) is False
