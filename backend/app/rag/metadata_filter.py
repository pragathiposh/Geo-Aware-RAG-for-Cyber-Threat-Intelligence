import re
from typing import Any

from langchain_core.documents import Document
from app.threat_analysis.normalization import CTINormalizer


class CTIMetadataFilter:
    """
    Metadata filtering utilities for the Cyber Threat Intelligence
    RAG system.

    Supported metadata fields:
        - countries
        - industries
        - malware_families
        - attack_ids
        - tags

    Filter behavior:
        - Multiple filter fields use AND logic.
        - Multiple values inside one filter use OR logic.
        - "|" is used as the separator for multiple search values.
        - Metadata values may be stored as lists or comma/pipe-separated strings.
    """

    # ------------------------------------------------------

    @classmethod
    def normalize_country(cls, value: Any) -> str:
        """Canonicalize known aliases without substring matching."""
        normalized = cls.normalize_value(value)
        if not normalized:
            return ""
        country = CTINormalizer.normalize_country(normalized)
        return (country or "").casefold()

    @classmethod
    def country_matches(cls, metadata_value: Any, search_value: str) -> bool:
        metadata_values = cls.split_metadata_values(metadata_value)
        requested_values = cls.split_search_values(search_value)
        metadata_countries = {
            cls.normalize_country(value) for value in metadata_values
        }
        requested_countries = {
            cls.normalize_country(value) for value in requested_values
        }
        metadata_countries.discard("")
        requested_countries.discard("")
        return bool(metadata_countries & requested_countries)

    # ------------------------------------------------------
    # Normalize metadata values
    # ------------------------------------------------------

    @staticmethod
    def normalize_value(value: Any) -> str:
        """
        Convert a metadata value into a normalized string.
        """

        if value is None:
            return ""

        return str(value).strip().lower()

    # ------------------------------------------------------
    # Split metadata values
    # ------------------------------------------------------

    @classmethod
    def split_metadata_values(cls, metadata_value: Any) -> list[str]:
        """
        Convert a metadata value into a list of normalized values.

        Examples:

            "United States, Canada"
            -> ["united states", "canada"]

            "United States|Canada"
            -> ["united states", "canada"]

            ["United States", "Canada"]
            -> ["united states", "canada"]
        """

        if metadata_value is None:
            return []

        # Metadata may already be stored as a list.
        if isinstance(metadata_value, list):
            values = []

            for item in metadata_value:
                normalized_item = cls.normalize_value(item)

                # A list item may itself contain multiple values.
                values.extend(
                    part.strip()
                    for part in re.split(r"[,|]", normalized_item)
                    if part.strip()
                )

            return values

        # Metadata may be stored as a string.
        normalized_value = cls.normalize_value(metadata_value)

        if not normalized_value:
            return []

        return [
            item.strip()
            for item in re.split(r"[,|]", normalized_value)
            if item.strip()
        ]

    # ------------------------------------------------------
    # Split search values
    # ------------------------------------------------------

    @classmethod
    def split_search_values(cls, search_value: str) -> list[str]:
        """
        Convert a filter value into multiple normalized search values.

        Example:

            "United States|Canada"
            -> ["united states", "canada"]
        """

        if not search_value:
            return []

        normalized_search_value = cls.normalize_value(search_value)

        return [
            item.strip()
            for item in re.split(r"[|]", normalized_search_value)
            if item.strip()
        ]

    # ------------------------------------------------------
    # Match a metadata field
    # ------------------------------------------------------

    @classmethod
    def field_contains(
        cls,
        metadata_value: Any,
        search_value: str,
    ) -> bool:
        """
        Determine whether a non-country metadata field contains a
        requested value. Country matching is handled separately with exact
        normalized equality in ``matches``.

        Multiple search values use OR logic.

        Example:

            metadata_value = "United States, Australia"
            search_value = "United States|Canada"

        Result:

            True

        because "United States" matches.

        Another example:

            metadata_value = "Australia"
            search_value = "United States|Canada"

        Result:

            False
        """

        if not search_value:
            return True

        if metadata_value is None:
            return False

        search_values = cls.split_search_values(search_value)

        if not search_values:
            return True

        metadata_values = cls.split_metadata_values(metadata_value)

        if not metadata_values:
            return False

        # OR logic between multiple search values.
        #
        # Example:
        #   search = ["united states", "canada"]
        #
        # matches:
        #   ["united states", "australia"]
        #
        # because "united states" is present.

        for search_item in search_values:

            for metadata_item in metadata_values:

                if search_item in metadata_item:
                    return True

        return False

    # ------------------------------------------------------
    # Match document metadata
    # ------------------------------------------------------

    @classmethod
    def matches(
        cls,
        document: Document,
        filters: dict[str, str],
    ) -> bool:
        """
        Determine whether a document satisfies all supplied
        metadata filters.

        Multiple fields use AND logic.

        Example:

            filters = {
                "countries": "united states",
                "industries": "healthcare",
            }

        A document must contain BOTH:

            country = United States
            AND
            industry = Healthcare
        """

        metadata = document.metadata

        for field, search_value in filters.items():

            if not search_value:
                continue

            metadata_value = metadata.get(field)

            if field == "countries":
                if not cls.country_matches(metadata_value, search_value):
                    return False
                continue

            if not cls.field_contains(
                metadata_value,
                search_value,
            ):
                return False

        return True

    # ------------------------------------------------------
    # Filter documents
    # ------------------------------------------------------

    @classmethod
    def filter_documents(
        cls,
        documents: list[Document],
        filters: dict[str, str],
    ) -> list[Document]:
        """
        Return only documents satisfying all metadata filters.

        Example:

            filters = {
                "countries": "United States|Canada",
                "industries": "Healthcare",
            }

        Means:

            (United States OR Canada)
            AND
            Healthcare
        """

        if not filters:
            return documents

        filtered_documents: list[Document] = []

        for document in documents:

            if cls.matches(
                document,
                filters,
            ):
                filtered_documents.append(document)

        return filtered_documents
