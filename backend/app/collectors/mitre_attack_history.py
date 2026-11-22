import json
from pathlib import Path
from typing import Any


ATTACK_DATA_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "mitre"
    / "enterprise-attack.json"
)


def load_attack_history() -> list[dict[str, Any]]:
    """
    Load historical, revoked, or deprecated MITRE ATT&CK
    attack-pattern objects from the Enterprise ATT&CK STIX bundle.

    The current ATT&CK loader intentionally removes revoked and
    deprecated techniques. This loader preserves those objects so
    that older CTI records can still be interpreted.
    """

    if not ATTACK_DATA_PATH.exists():
        raise FileNotFoundError(
            f"MITRE ATT&CK dataset not found: "
            f"{ATTACK_DATA_PATH}"
        )

    with ATTACK_DATA_PATH.open(
        "r",
        encoding="utf-8",
    ) as file:
        bundle = json.load(file)

    historical_objects: list[dict[str, Any]] = []

    for obj in bundle.get("objects", []):

        if obj.get("type") != "attack-pattern":
            continue

        is_revoked = obj.get(
            "revoked",
            False,
        )

        is_deprecated = obj.get(
            "x_mitre_deprecated",
            False,
        )

        if is_revoked or is_deprecated:
            historical_objects.append(obj)

    return historical_objects