from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ATTACKEnrichmentStatus(str, Enum):
    """
    Describes the status of MITRE ATT&CK enrichment.
    """

    ACTIVE = "active"
    HISTORICAL = "historical"
    UNRESOLVED = "unresolved"


class CTIIndicator(BaseModel):
    """
    Represents an Indicator of Compromise (IOC).
    """

    indicator_type: str | None = None

    value: str

    confidence: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
    )

    description: str | None = None


class CTIThreatActor(BaseModel):
    """
    Represents a threat actor associated with a CTI record.
    """

    name: str

    aliases: list[str] = Field(
        default_factory=list
    )

    description: str | None = None


class CTIMalware(BaseModel):
    """
    Represents malware associated with a CTI record.
    """

    name: str

    family: str | None = None

    aliases: list[str] = Field(
        default_factory=list
    )

    description: str | None = None


class CTIAttackTechnique(BaseModel):
    """
    Represents a MITRE ATT&CK technique or sub-technique.
    """

    attack_id: str

    name: str | None = None

    description: str | None = None

    tactics: list[str] = Field(
        default_factory=list
    )

    platforms: list[str] = Field(
        default_factory=list
    )

    enrichment_status: ATTACKEnrichmentStatus = (
        ATTACKEnrichmentStatus.UNRESOLVED
    )

    enrichment_source: str | None = None


class CTIGeography(BaseModel):
    """
    Represents geographic context associated with a CTI record.

    The country/region represents the geographic association
    contained in the source CTI data. It should not automatically
    be interpreted as attacker origin.
    """

    countries: list[str] = Field(
        default_factory=list
    )

    regions: list[str] = Field(
        default_factory=list
    )

    continent: str | None = None


class GeographicEvidenceRole(str, Enum):
    INCIDENT_LOCATION = "incident_location"
    TARGET_LOCATION = "target_location"
    VICTIM_LOCATION = "victim_location"
    INFRASTRUCTURE_LOCATION = "infrastructure_location"
    CLAIMED_ACTOR_ORIGIN = "claimed_actor_origin"
    GENERAL_MENTION = "general_mention"


class GeographicEvidenceStatus(str, Enum):
    SUPPORTED = "supported"
    AMBIGUOUS = "ambiguous"
    NEGATED = "negated"


class CTIGeographicEvidence(BaseModel):
    """A location claim grounded in an explicit source description span."""

    country: str | None = None
    region: str | None = None
    role: GeographicEvidenceRole = GeographicEvidenceRole.GENERAL_MENTION
    evidence_text: str
    start_char: int | None = Field(default=None, ge=0)
    end_char: int | None = Field(default=None, ge=0)
    source_record_id: str
    extraction_method: str
    confidence: float = Field(ge=0.0, le=1.0)
    status: GeographicEvidenceStatus = GeographicEvidenceStatus.AMBIGUOUS
    provenance: str = "source_description"
    uncertainty: str | None = None


class CTITarget(BaseModel):
    """
    Represents organizations or sectors targeted by a threat.
    """

    industries: list[str] = Field(
        default_factory=list
    )

    organizations: list[str] = Field(
        default_factory=list
    )


class CTIRecord(BaseModel):
    """
    Canonical representation of a Cyber Threat Intelligence record.

    This schema provides a normalized representation of CTI data
    independent of the original source format.
    """

    record_id: str

    title: str

    description: str = ""

    source: str | None = None

    author: str | None = None

    tlp: str | None = None

    created_at: datetime | None = None

    modified_at: datetime | None = None

    tags: list[str] = Field(
        default_factory=list
    )

    threat_actors: list[CTIThreatActor] = Field(
        default_factory=list
    )

    malware: list[CTIMalware] = Field(
        default_factory=list
    )

    attack_techniques: list[CTIAttackTechnique] = Field(
        default_factory=list
    )

    vulnerabilities: list[str] = Field(
        default_factory=list
    )

    geography: CTIGeography = Field(
        default_factory=CTIGeography
    )

    # Deliberately separate from geography.countries, which retain source tags.
    geographic_evidence: list[CTIGeographicEvidence] = Field(default_factory=list)

    targets: CTITarget = Field(
        default_factory=CTITarget
    )

    indicators: list[CTIIndicator] = Field(
        default_factory=list
    )

    raw_metadata: dict[str, Any] = Field(
        default_factory=dict
    )
