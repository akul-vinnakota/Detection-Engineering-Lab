from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class EnrichmentInput:
    detection_name: str
    severity: str
    mitre_attack: list[str]
    host: str
    user: str
    source_process: str
    command_line: str
    source_ip: str
    raw_event: dict[str, Any]


def normalize_alert(alert: dict[str, Any]) -> dict[str, Any]:
    event = alert.get("event", {})

    mitre = alert.get("mitre_attack", [])

    if isinstance(mitre, str):
        mitre = [mitre]

    normalized = EnrichmentInput(
        detection_name=str(alert.get("rule", "Unknown Detection")),
        severity=str(alert.get("severity", "unknown")),
        mitre_attack=mitre,
        host=str(
            event.get("Computer")
            or alert.get("computer")
            or "unknown"
        ),
        user=str(
            event.get("User")
            or event.get("SourceUser")
            or event.get("SubjectUserName")
            or "unknown"
        ),
        source_process=str(
            event.get("SourceImage")
            or event.get("Image")
            or "unknown"
        ),
        command_line=str(event.get("CommandLine", "")),
        source_ip=str(
            event.get("SourceIp")
            or event.get("SourceIP")
            or event.get("IpAddress")
            or "unknown"
        ),
        raw_event=event,
    )

    return asdict(normalized)
