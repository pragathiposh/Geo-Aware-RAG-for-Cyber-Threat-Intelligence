from app.collectors.mitre_attack import load_attack


def test_mitre_attack_loader():
    techniques = load_attack()

    assert techniques
    assert len(techniques) > 0

    print(f"Loaded MITRE ATT&CK techniques: {len(techniques)}")


def test_known_attack_techniques():
    techniques = load_attack()

    technique_ids = set()

    for technique in techniques:
        external_references = getattr(
            technique,
            "external_references",
            []
        )

        for reference in external_references:
            external_id = getattr(
                reference,
                "external_id",
                None
            )

            if external_id:
                technique_ids.add(external_id)

    expected_ids = {
        "T1027",
        "T1059.001",
        "T1082",
        "T1105",
        "T1566",
        "T1486",
    }

    for technique_id in expected_ids:
        assert technique_id in technique_ids, (
            f"Missing MITRE technique: {technique_id}"
        )

    print("Known MITRE ATT&CK technique IDs verified.")


if __name__ == "__main__":
    test_mitre_attack_loader()
    test_known_attack_techniques()