import json
from pathlib import Path


ENTERPRISE_PATH = Path(
    "data/mitre/enterprise-attack.json"
)


def load_external_ids(path: Path) -> set[str]:
    with path.open(
        "r",
        encoding="utf-8"
    ) as file:
        bundle = json.load(file)

    ids = set()

    for obj in bundle.get("objects", []):

        if obj.get("type") != "attack-pattern":
            continue

        for reference in obj.get(
            "external_references",
            []
        ):

            external_id = reference.get(
                "external_id"
            )

            if external_id:
                ids.add(external_id)

    return ids


def test_attack_domain_diagnostics():

    unresolved_ids = {
        "T1398",
        "T1402",
        "T1406",
        "T1407",
        "T1409",
        "T1412",
        "T1417",
        "T1420",
        "T1426",
        "T1430",
        "T1433",
        "T1437",
        "T1444",
        "T1454",
        "T1464",
        "T1471",
        "T1481",
        "T1508",
        "T1509",
        "T1513",
        "T1516",
        "T1533",
        "T1541",
        "T1581",
        "T1582",
        "T1603",
    }

    enterprise_ids = load_external_ids(
        ENTERPRISE_PATH
    )

    enterprise_matches = (
        unresolved_ids & enterprise_ids
    )

    print()
    print("=" * 60)
    print("ATT&CK DOMAIN DIAGNOSTIC")
    print("=" * 60)

    print(
        f"IDs checked:             "
        f"{len(unresolved_ids)}"
    )

    print(
        f"Enterprise matches:      "
        f"{len(enterprise_matches)}"
    )

    print(
        f"Not Enterprise:          "
        f"{len(unresolved_ids - enterprise_ids)}"
    )

    if enterprise_matches:
        print()
        print("Enterprise matches:")

        for attack_id in sorted(
            enterprise_matches
        ):
            print(f"  - {attack_id}")

    print()
    print("IDs not in Enterprise:")

    for attack_id in sorted(
        unresolved_ids - enterprise_ids
    ):
        print(f"  - {attack_id}")

    print("=" * 60)

    assert unresolved_ids


if __name__ == "__main__":
    test_attack_domain_diagnostics()