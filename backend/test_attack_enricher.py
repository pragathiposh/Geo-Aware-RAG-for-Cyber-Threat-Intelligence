from app.collectors.mitre_attack import load_attack
from app.threat_analysis.attack_enricher import ATTACKEnricher
from app.threat_analysis.cti_schema import (
    ATTACKEnrichmentStatus,
    CTIAttackTechnique,
    CTIRecord,
)


def test_attack_enrichment():

    techniques = load_attack()

    enricher = ATTACKEnricher(
        techniques
    )

    record = CTIRecord(
        record_id="test-record",
        title="Test CTI Record",
        attack_techniques=[
            CTIAttackTechnique(
                attack_id="T1027"
            ),
            CTIAttackTechnique(
                attack_id="T1059.001"
            ),
        ],
    )

    enriched_record = (
        enricher.enrich_record(
            record
        )
    )

    assert len(
        enriched_record.attack_techniques
    ) == 2

    for technique in (
        enriched_record.attack_techniques
    ):

        assert technique.attack_id

        assert technique.name

        assert technique.description

        assert (
            technique.enrichment_status
            == ATTACKEnrichmentStatus.ACTIVE
        )

        assert (
            technique.enrichment_source
            == "MITRE Enterprise ATT&CK"
        )

    print()
    print(
        "ACTIVE ATT&CK enrichment successful."
    )

    for technique in (
        enriched_record.attack_techniques
    ):

        print()

        print(
            f"ID: {technique.attack_id}"
        )

        print(
            f"Name: {technique.name}"
        )

        print(
            f"Tactics: {technique.tactics}"
        )

        print(
            f"Platforms: {technique.platforms}"
        )

        print(
            "Status: "
            f"{technique.enrichment_status.value}"
        )

        print(
            "Source: "
            f"{technique.enrichment_source}"
        )


if __name__ == "__main__":
    test_attack_enrichment()