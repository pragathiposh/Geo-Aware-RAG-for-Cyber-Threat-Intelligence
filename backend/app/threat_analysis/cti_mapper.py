from datetime import datetime
from typing import Any

from app.threat_analysis.cti_schema import (
    CTIAttackTechnique,
    CTIGeography,
    CTIMalware,
    CTIRecord,
    CTITarget,
)


class CTIRecordMapper:
    """
    Converts the current OTX-style CSV metadata into
    the canonical CTIRecord schema.
    """

    @staticmethod
    def split_values(value: Any) -> list[str]:
        if value is None:
            return []

        text = str(value).strip()

        if not text:
            return []

        parts = [
            part.strip()
            for part in text.replace("|", ",").split(",")
        ]

        return [
            part
            for part in parts
            if part
        ]

    @staticmethod
    def parse_datetime(value: Any) -> datetime | None:
        if value is None:
            return None

        text = str(value).strip()

        if not text:
            return None

        try:
            return datetime.fromisoformat(
                text.replace("Z", "+00:00")
            )
        except ValueError:
            return None

    @classmethod
    def from_metadata(
        cls,
        metadata: dict[str, Any],
        description: str = "",
    ) -> CTIRecord:

        countries = cls.split_values(
            metadata.get("countries")
        )

        industries = cls.split_values(
            metadata.get("industries")
        )

        malware_names = cls.split_values(
            metadata.get("malware_families")
        )

        attack_ids = cls.split_values(
            metadata.get("attack_ids")
        )

        tags = cls.split_values(
            metadata.get("tags")
        )

        malware = [
            CTIMalware(name=name)
            for name in malware_names
        ]

        attack_techniques = [
            CTIAttackTechnique(
                attack_id=attack_id
            )
            for attack_id in attack_ids
        ]

        geography = CTIGeography(
            countries=countries
        )

        targets = CTITarget(
            industries=industries
        )

        record_id = str(
            metadata.get("pulse_id")
            or metadata.get("id")
            or metadata.get("record_id")
            or metadata.get("source_record_id")
            or ""
        )

        title = str(
            metadata.get("title")
            or "Untitled CTI Record"
        )

        raw_metadata = dict(metadata)

        return CTIRecord(
            record_id=record_id,
            title=title,
            description=description,
            source=metadata.get("source"),
            author=metadata.get("author"),
            tlp=metadata.get("tlp"),
            created_at=cls.parse_datetime(
                metadata.get("created")
            ),
            modified_at=cls.parse_datetime(
                metadata.get("modified")
            ),
            tags=tags,
            malware=malware,
            attack_techniques=attack_techniques,
            geography=geography,
            targets=targets,
            raw_metadata=raw_metadata,
        )
