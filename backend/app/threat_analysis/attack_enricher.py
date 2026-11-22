
from typing import Any

from app.threat_analysis.cti_schema import (
    ATTACKEnrichmentStatus,
    CTIAttackTechnique,
    CTIRecord,
)


class ATTACKEnricher:
    """
    Enriches CTI ATT&CK technique references using:

    1. Current MITRE Enterprise ATT&CK techniques
    2. Historical/revoked/deprecated ATT&CK techniques

    If a technique cannot be found in either source, it is marked
    as UNRESOLVED rather than being silently discarded.

    Supports both:
    - Current ATT&CK objects
    - Historical STIX dictionaries
    """

    CURRENT_SOURCE = "MITRE Enterprise ATT&CK"

    HISTORICAL_SOURCE = (
        "MITRE Enterprise ATT&CK (historical)"
    )

    def __init__(
        self,
        techniques: list[Any],
        historical_techniques: list[Any] | None = None,
    ):
        self.techniques_by_id: dict[str, Any] = {}

        self.historical_by_id: dict[str, Any] = {}

        # ---------------------------------------------------------
        # Index current active ATT&CK techniques
        # ---------------------------------------------------------

        for technique in techniques:
            self._index_technique(
                technique,
                self.techniques_by_id,
            )

        # ---------------------------------------------------------
        # Index historical/revoked/deprecated techniques
        # ---------------------------------------------------------

        for technique in historical_techniques or []:
            self._index_technique(
                technique,
                self.historical_by_id,
            )

    # -------------------------------------------------------------
    # UNIVERSAL VALUE ACCESSOR
    # -------------------------------------------------------------

    @staticmethod
    def _get_value(
        item: Any,
        key: str,
        default: Any = None,
    ) -> Any:
        """
        Read a value from either a dictionary or an object.

        Supports historical STIX dictionaries and current
        ATT&CK objects.
        """

        if isinstance(item, dict):
            return item.get(key, default)

        return getattr(
            item,
            key,
            default,
        )

    # -------------------------------------------------------------
    # INDEX ATT&CK TECHNIQUES
    # -------------------------------------------------------------

    @staticmethod
    def _index_technique(
        technique: Any,
        index: dict[str, Any],
    ) -> None:
        """
        Add all external ATT&CK IDs associated with a technique
        to the supplied lookup index.

        Supports both dictionaries and objects.
        """

        external_references = (
            ATTACKEnricher._get_value(
                technique,
                "external_references",
                [],
            )
        )

        for reference in external_references:

            external_id = (
                ATTACKEnricher._get_value(
                    reference,
                    "external_id",
                )
            )

            if external_id:
                index[external_id] = technique

    # -------------------------------------------------------------
    # EXTRACT ATT&CK METADATA
    # -------------------------------------------------------------

    @staticmethod
    def _extract_metadata(
        technique: Any,
    ) -> tuple[
        str | None,
        str | None,
        list[str],
        list[str],
    ]:
        """
        Extract name, description, tactics, and platforms.

        Supports both current ATT&CK objects and historical
        STIX dictionaries.
        """

        get_value = ATTACKEnricher._get_value

        name = get_value(
            technique,
            "name",
        )

        description = get_value(
            technique,
            "description",
        )

        # ---------------------------------------------------------
        # Extract ATT&CK tactics
        # ---------------------------------------------------------

        kill_chain_phases = get_value(
            technique,
            "kill_chain_phases",
            [],
        )

        tactics: list[str] = []

        for phase in kill_chain_phases:

            tactic = get_value(
                phase,
                "phase_name",
            )

            if tactic:
                tactics.append(tactic)

        tactics = sorted(
            set(tactics)
        )

        # ---------------------------------------------------------
        # Extract supported platforms
        # ---------------------------------------------------------

        platforms = get_value(
            technique,
            "x_mitre_platforms",
            [],
        )

        if platforms is None:
            platforms = []

        return (
            name,
            description,
            tactics,
            list(platforms),
        )

    # -------------------------------------------------------------
    # ENRICH INDIVIDUAL ATT&CK TECHNIQUE
    # -------------------------------------------------------------

    def enrich_technique(
        self,
        technique: CTIAttackTechnique,
    ) -> CTIAttackTechnique:
        """
        Enrich one CTI ATT&CK technique.

        Resolution order:

        1. Current active ATT&CK
        2. Historical/revoked/deprecated ATT&CK
        3. Unresolved
        """

        attack_id = technique.attack_id

        # =========================================================
        # 1. CURRENT ACTIVE ATT&CK
        # =========================================================

        mitre_technique = self.techniques_by_id.get(
            attack_id
        )

        if mitre_technique is not None:

            (
                name,
                description,
                tactics,
                platforms,
            ) = self._extract_metadata(
                mitre_technique
            )

            return CTIAttackTechnique(
                attack_id=attack_id,
                name=name or technique.name,
                description=(
                    description
                    or technique.description
                ),
                tactics=tactics,
                platforms=platforms,
                enrichment_status=(
                    ATTACKEnrichmentStatus.ACTIVE
                ),
                enrichment_source=(
                    self.CURRENT_SOURCE
                ),
            )

        # =========================================================
        # 2. HISTORICAL ATT&CK
        # =========================================================

        historical_technique = (
            self.historical_by_id.get(
                attack_id
            )
        )

        if historical_technique is not None:

            (
                name,
                description,
                tactics,
                platforms,
            ) = self._extract_metadata(
                historical_technique
            )

            return CTIAttackTechnique(
                attack_id=attack_id,
                name=name or technique.name,
                description=(
                    description
                    or technique.description
                ),
                tactics=tactics,
                platforms=platforms,
                enrichment_status=(
                    ATTACKEnrichmentStatus.HISTORICAL
                ),
                enrichment_source=(
                    self.HISTORICAL_SOURCE
                ),
            )

        # =========================================================
        # 3. UNRESOLVED
        # =========================================================

        return technique.model_copy(
            update={
                "enrichment_status": (
                    ATTACKEnrichmentStatus.UNRESOLVED
                ),
                "enrichment_source": None,
            }
        )

    # -------------------------------------------------------------
    # ENRICH COMPLETE CTI RECORD
    # -------------------------------------------------------------

    def enrich_record(
        self,
        record: CTIRecord,
    ) -> CTIRecord:
        """
        Enrich every ATT&CK technique contained in a CTI record.
        """

        enriched_techniques = [
            self.enrich_technique(
                technique
            )
            for technique in record.attack_techniques
        ]

        return record.model_copy(
            update={
                "attack_techniques": (
                    enriched_techniques
                ),
            }
        )
