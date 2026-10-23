import json
from pathlib import Path
from typing import Any


CATALOG_FILE = Path("ai/attack_catalog.json")


def load_attack_catalog() -> dict[str, dict[str, Any]]:
    if not CATALOG_FILE.exists():
        raise FileNotFoundError(
            f"ATT&CK catalog not found: {CATALOG_FILE}"
        )

    return json.loads(
        CATALOG_FILE.read_text(encoding="utf-8")
    )


def enrich_attack_techniques(
    technique_ids: list[str],
) -> dict[str, list]:
    catalog = load_attack_catalog()

    validated = []
    unknown = []

    for technique_id in technique_ids:
        technique = catalog.get(technique_id)

        if technique is None:
            unknown.append(technique_id)
            continue

        validated.append(
            {
                "technique_id": technique_id,
                "technique_name": technique["name"],
                "tactics": technique["tactics"],
            }
        )

    return {
        "validated": validated,
        "unknown": unknown,
    }
