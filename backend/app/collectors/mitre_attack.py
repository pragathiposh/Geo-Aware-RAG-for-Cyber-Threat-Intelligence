from mitreattack.stix20 import MitreAttackData

def load_attack():
    attack = MitreAttackData("enterprise-attack.json")

    techniques = attack.get_techniques(
        remove_revoked_deprecated=True
    )

    return techniques