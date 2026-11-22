import re
from typing import Any

from app.threat_analysis.cti_schema import (
    CTIAttackTechnique,
    CTIGeography,
    CTIMalware,
    CTIRecord,
    CTITarget,
)


class CTINormalizer:
    """
    Normalizes canonical CTI records.

    The normalizer standardizes values while preserving
    the original CTI record and source metadata.
    """

    UNKNOWN_VALUES = {
        "",
        "unknown",
        "n/a",
        "na",
        "none",
        "null",
        "not available",
        "not applicable",
    }

    COUNTRY_ALIASES = {
        "us": "United States",
        "usa": "United States",
        "u.s.": "United States",
        "u.s.a.": "United States",
        "united states": "United States",
        "united states of america": "United States",

        "uk": "United Kingdom",
        "u.k.": "United Kingdom",
        "united kingdom": "United Kingdom",
        "united kingdom of great britain and northern ireland": (
            "United Kingdom"
        ),
        "great britain": "United Kingdom",

        "uae": "United Arab Emirates",
        "u.a.e.": "United Arab Emirates",
        "united arab emirates": "United Arab Emirates",

        "india": "India",
        "canada": "Canada",
        "australia": "Australia",
        "germany": "Germany",
        "france": "France",
        "japan": "Japan",
        "china": "China",
        "singapore": "Singapore",
        "portugal": "Portugal",
        "israel": "Israel",
        "iran": "Iran",
        "croatia": "Croatia",
        "spain": "Spain",
        "taiwan": "Taiwan",
        "thailand": "Thailand",
        "slovakia": "Slovakia",
    }

    INDUSTRY_ALIASES = {
        "health": "Healthcare",
        "healthcare": "Healthcare",
        "health care": "Healthcare",
        "healthcare sector": "Healthcare",

        "finance": "Finance",
        "financial": "Finance",
        "financial services": "Finance",
        "banking": "Finance",

        "it": "Technology",
        "information technology": "Technology",
        "technology": "Technology",

        "education": "Education",

        "government": "Government",

        "defense": "Defense",
        "defence": "Defense",

        "manufacturing": "Manufacturing",

        "transportation": "Transportation",

        "energy": "Energy",

        "construction": "Construction",

        "business services": "Business Services",

        "critical infrastructure": "Critical Infrastructure",
    }

    @classmethod
    def normalize_unknown(
        cls,
        value: Any,
    ) -> str | None:
        """
        Convert known unknown-like values to None.
        """

        if value is None:
            return None

        normalized = str(value).strip()

        if normalized.lower() in cls.UNKNOWN_VALUES:
            return None

        return normalized

    @classmethod
    def normalize_country(
        cls,
        country: str,
    ) -> str | None:

        value = cls.normalize_unknown(country)

        if value is None:
            return None

        key = value.lower().strip()

        return cls.COUNTRY_ALIASES.get(
            key,
            value,
        )

    @classmethod
    def normalize_industry(
        cls,
        industry: str,
    ) -> str | None:

        value = cls.normalize_unknown(industry)

        if value is None:
            return None

        key = value.lower().strip()

        return cls.INDUSTRY_ALIASES.get(
            key,
            value,
        )

    @staticmethod
    def normalize_attack_id(
        attack_id: str,
    ) -> str | None:

        if not attack_id:
            return None

        value = attack_id.strip().upper()

        if not value:
            return None

        pattern = r"^T\d{4}(?:\.\d{3})?$"

        if not re.match(pattern, value):
            return None

        return value

    @staticmethod
    def normalize_text(
        value: str | None,
    ) -> str | None:

        if value is None:
            return None

        normalized = re.sub(
            r"\s+",
            " ",
            value,
        ).strip()

        return normalized or None

    @classmethod
    def normalize_geography(
        cls,
        geography: CTIGeography,
    ) -> CTIGeography:

        normalized_countries = []

        for country in geography.countries:

            normalized_country = cls.normalize_country(
                country
            )

            if normalized_country:
                normalized_countries.append(
                    normalized_country
                )

        return CTIGeography(
            countries=sorted(
                set(normalized_countries)
            ),
            regions=sorted(
                set(
                    region.strip()
                    for region in geography.regions
                    if region.strip()
                )
            ),
            continent=cls.normalize_unknown(
                geography.continent
            ),
        )

    @classmethod
    def normalize_targets(
        cls,
        targets: CTITarget,
    ) -> CTITarget:

        normalized_industries = []

        for industry in targets.industries:

            normalized_industry = cls.normalize_industry(
                industry
            )

            if normalized_industry:
                normalized_industries.append(
                    normalized_industry
                )

        return CTITarget(
            industries=sorted(
                set(normalized_industries)
            ),
            organizations=sorted(
                set(
                    organization.strip()
                    for organization in targets.organizations
                    if organization.strip()
                )
            ),
        )

    @classmethod
    def normalize_malware(
        cls,
        malware: list[CTIMalware],
    ) -> list[CTIMalware]:

        normalized = []

        for item in malware:

            name = cls.normalize_unknown(
                item.name
            )

            if not name:
                continue

            name = cls.normalize_text(name)

            if not name:
                continue

            aliases = []

            for alias in item.aliases:

                normalized_alias = cls.normalize_unknown(
                    alias
                )

                if normalized_alias:
                    normalized_alias = cls.normalize_text(
                        normalized_alias
                    )

                if normalized_alias:
                    aliases.append(
                        normalized_alias
                    )

            normalized.append(
                CTIMalware(
                    name=name,
                    family=cls.normalize_unknown(
                        item.family
                    ),
                    aliases=sorted(
                        set(aliases)
                    ),
                    description=cls.normalize_text(
                        item.description
                    ),
                )
            )

        return normalized

    @classmethod
    def normalize_attack_techniques(
        cls,
        techniques: list[CTIAttackTechnique],
    ) -> list[CTIAttackTechnique]:
        normalized = []

        for technique in techniques:
            attack_id = cls.normalize_attack_id(
                technique.attack_id
            )

            if not attack_id:
                continue

            normalized_tactics = []

            for tactic in technique.tactics:
                normalized_tactic = cls.normalize_text(tactic)

                if normalized_tactic:
                    normalized_tactics.append(normalized_tactic)

            normalized_tactics = sorted(set(normalized_tactics))

            normalized.append(
                CTIAttackTechnique(
                    attack_id=attack_id,
                    name=cls.normalize_text(
                        technique.name
                    ),
                    description=cls.normalize_text(
                        technique.description
                    ),
                    tactics=normalized_tactics,
                    platforms=sorted(
                        set(
                            platform.strip()
                            for platform in technique.platforms
                            if platform and platform.strip()
                        )
                    ),
                )
            )

        unique = {}

        for technique in normalized:
            unique[technique.attack_id] = technique

        return list(unique.values())

    @classmethod
    def normalize_record(
        cls,
        record: CTIRecord,
    ) -> CTIRecord:

        normalized_tags = []

        for tag in record.tags:

            normalized_tag = cls.normalize_text(
                tag
            )

            if normalized_tag:
                normalized_tags.append(
                    normalized_tag
                )

        normalized_vulnerabilities = []

        for vulnerability in record.vulnerabilities:

            normalized_vulnerability = (
                cls.normalize_text(
                    vulnerability
                )
            )

            if normalized_vulnerability:
                normalized_vulnerabilities.append(
                    normalized_vulnerability
                )

        return record.model_copy(
            update={
                "title": cls.normalize_text(
                    record.title
                ) or "Untitled CTI Record",

                "description": (
                    cls.normalize_text(
                        record.description
                    )
                    or ""
                ),

                "author": cls.normalize_text(
                    record.author
                ),

                "tlp": (
                    cls.normalize_text(
                        record.tlp
                    )
                    or None
                ),

                "tags": sorted(
                    set(normalized_tags)
                ),

                "malware": cls.normalize_malware(
                    record.malware
                ),

                "attack_techniques": (
                    cls.normalize_attack_techniques(
                        record.attack_techniques
                    )
                ),

                "vulnerabilities": sorted(
                    set(normalized_vulnerabilities)
                ),

                "geography": cls.normalize_geography(
                    record.geography
                ),

                "targets": cls.normalize_targets(
                    record.targets
                ),
            }
        )