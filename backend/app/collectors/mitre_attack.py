from pathlib import Path

from mitreattack.stix20 import MitreAttackData


ATTACK_DATA_PATH = (
    Path(__file__).resolve().parents[2]
    / "data"
    / "mitre"
    / "enterprise-attack.json"
)


def load_attack():
    if not ATTACK_DATA_PATH.exists():
        raise FileNotFoundError(
            f"MITRE ATT&CK dataset not found: {ATTACK_DATA_PATH}"
        )

    attack = MitreAttackData(str(ATTACK_DATA_PATH))

    techniques = attack.get_techniques(
        remove_revoked_deprecated=True
    )

    return techniques