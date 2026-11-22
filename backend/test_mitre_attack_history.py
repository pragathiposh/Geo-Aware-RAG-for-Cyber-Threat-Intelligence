from app.collectors.mitre_attack_history import (
    load_attack_history,
)


def test_mitre_attack_history():

    historical = load_attack_history()

    assert historical
    assert len(historical) > 0

    print(
        f"Historical/revoked ATT&CK objects: "
        f"{len(historical)}"
    )

    external_ids = set()

    for technique in historical:
        for reference in technique.get(
            "external_references",
            [],
        ):
            external_id = reference.get(
                "external_id"
            )

            if external_id:
                external_ids.add(
                    external_id
                )

    print(
        f"Historical/revoked ATT&CK IDs: "
        f"{len(external_ids)}"
    )

    assert external_ids


if __name__ == "__main__":
    test_mitre_attack_history()