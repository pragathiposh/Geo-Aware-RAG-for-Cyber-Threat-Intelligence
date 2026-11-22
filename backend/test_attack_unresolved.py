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


def test_unresolved_attack_enrichment():

    current = load_attack()

    historical = load_attack_history()

    enricher = ATTACKEnricher(
        current,
        historical,
    )

    # Deliberately fake/non-existent ATT&CK ID
    technique = CTIAttackTechnique(
        attack_id="T9999.999"
    )

    enriched = (
        enricher.enrich_technique(
            technique
        )
    )

    assert (
        enriched.enrichment_status
        == ATTACKEnrichmentStatus.UNRESOLVED
    )

    assert (
        enriched.enrichment_source
        is None
    )

    print()

    print(
        "Unresolved ATT&CK enrichment:"
    )

    print(
        f"ID: {enriched.attack_id}"
    )

    print(
        "Status: "
        f"{enriched.enrichment_status.value}"
    )

    print(
        f"Source: {enriched.enrichment_source}"
    )


if __name__ == "__main__":
    test_unresolved_attack_enrichment()