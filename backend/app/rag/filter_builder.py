from typing import Any
from app.geo.geo_resolver import GeoResolver


class CTIFilterBuilder:
    """
    Converts structured query information produced by the
    CTI query parser into metadata filters understood by
    the RAG retriever.
    """

    @staticmethod
    def build_filters(
        parsed_query: dict[str, Any],
    ) -> dict[str, str]:
        """
        Build metadata filters from parsed CTI query data.

        Supported mappings:

            country   -> countries
            industry  -> industries
            malware   -> malware_families
            attack_id -> attack_ids

        Threat type is intentionally not mapped yet because
        the current dataset does not contain a dedicated
        threat_type metadata field.
        """

        if not parsed_query:
            return {}

        filters: dict[str, str] = {}

        country = parsed_query.get(
            "country"
        )

        if country:
            filters["countries"] = country

        region = parsed_query.get(
            "region"
        )

        if region and not country:

            region_info = GeoResolver.resolve_region(
                region
            )

            countries = region_info.get(
                "countries",
                []
            )

            if countries:
                filters["countries"] = "|".join(
                    countries
                )

        industry = parsed_query.get(
            "industry"
        )

        if industry:
            filters["industries"] = industry

        malware = parsed_query.get(
            "malware"
        )

        if malware:
            filters["malware_families"] = malware

        attack_id = parsed_query.get(
            "attack_id"
        )

        if attack_id:
            filters["attack_ids"] = attack_id

        return filters