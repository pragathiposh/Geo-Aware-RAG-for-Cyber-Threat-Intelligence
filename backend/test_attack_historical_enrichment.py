from app.collectors.mitre_attack import load_attack
from app.collectors.mitre_attack_history import (
    load_attack_history,
)
from app.threat_analysis.attack_enricher import (
    ATTACKEnricher,
)
from app.threat_analysis.cti_schema import (
    ATTACKEnrichmentStatus,
    CTIAttackTechnique,
)


def test_historical_attack_enrichment():

    # ---------------------------------------------------------
    # Load current ATT&CK
    # ---------------------------------------------------------

    current = load_attack()

    # ---------------------------------------------------------
    # Load historical/revoked/deprecated ATT&CK
    # ---------------------------------------------------------

    historical = load_attack_history()

    # ---------------------------------------------------------
    # Create enricher using both knowledge sources
    # ---------------------------------------------------------

    enricher = ATTACKEnricher(
        current,
        historical,
    )

    # ---------------------------------------------------------
    # IMPORTANT:
    #
    # T1009 was identified by our previous diagnostic as a
    # revoked/deprecated ATT&CK technique in the supplied
    # Enterprise ATT&CK bundle.
    #
    # Do NOT use T1070.001 here.
    # ---------------------------------------------------------

    technique = CTIAttackTechnique(
        attack_id="T1009"
    )

    enriched = (
        enricher.enrich_technique(
            technique
        )
    )

    # ---------------------------------------------------------
    # Verify historical status
    # ---------------------------------------------------------

    assert (
        enriched.enrichment_status
        == ATTACKEnrichmentStatus.HISTORICAL
    )

    assert (
        enriched.enrichment_source
        == "MITRE Enterprise ATT&CK (historical)"
    )

    assert enriched.name

    # ---------------------------------------------------------
    # Display result
    # ---------------------------------------------------------

    print()

    print(
        "Historical ATT&CK enrichment:"
    )

    print(
        f"ID: {enriched.attack_id}"
    )

    print(
        f"Name: {enriched.name}"
    )

    print(
        "Status: "
        f"{enriched.enrichment_status.value}"
    )

    print(
        "Source: "
        f"{enriched.enrichment_source}"
    )

    print(
        f"Tactics: {enriched.tactics}"
    )

    print(
        f"Platforms: {enriched.platforms}"
    )


if __name__ == "__main__":
    test_historical_attack_enrichment()