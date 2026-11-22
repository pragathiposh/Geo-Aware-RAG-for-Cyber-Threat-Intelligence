import re
from typing import Any


class CTIQueryParser:
    """
    Rule-based query understanding for Cyber Threat Intelligence.

    Extracts structured CTI entities from natural-language queries:

        - threat type
        - country
        - industry
        - malware family
        - MITRE ATT&CK technique ID

    This is the first version of the query-understanding layer.
    Later it can be replaced or enhanced with NLP/LLM-based
    entity extraction.
    """

    THREAT_TYPES = [
        "ransomware",
        "phishing",
        "malware",
        "trojan",
        "botnet",
        "spyware",
        "ddos",
        "denial of service",
        "credential theft",
        "data breach",
        "exploit",
    ]

    COUNTRIES = {
        "united states": "United States",
        "united states of america": "United States",
        "usa": "United States",
        "us": "United States",

        "united kingdom": "United Kingdom",
        "uk": "United Kingdom",

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
        "united arab emirates": "United Arab Emirates",
    }

    INDUSTRIES = [
        "healthcare",
        "health",
        "finance",
        "financial",
        "banking",
        "manufacturing",
        "technology",
        "it",
        "education",
        "government",
        "defense",
        "transportation",
        "energy",
        "construction",
        "critical infrastructure",
        "business services",
    ]

    REGIONS = [
        "North America",
        "Europe",
        "South Asia",
        "East Asia",
        "Southeast Asia",
        "Middle East",
        "Oceania",
    ]

    @staticmethod
    def normalize_query(query: str) -> str:
        """
        Normalize the user query for easier matching.
        """

        query = query.lower().strip()

        query = re.sub(
            r"\s+",
            " ",
            query,
        )

        return query

    def extract_threat_type(
        self,
        query: str,
    ) -> str | None:

        for threat_type in self.THREAT_TYPES:

            if threat_type in query:

                return threat_type

        return None

    def extract_country(
        self,
        query: str,
    ) -> str | None:

        # Check longer country names first.
        countries = sorted(
            self.COUNTRIES.items(),
            key=lambda item: len(item[0]),
            reverse=True,
        )

        for country_alias, canonical_name in countries:

            pattern = rf"\b{re.escape(country_alias)}\b"

            if re.search(
                pattern,
                query,
            ):

                return canonical_name

        return None

    def extract_industry(
        self,
        query: str,
    ) -> str | None:

        industries = sorted(
            self.INDUSTRIES,
            key=len,
            reverse=True,
        )

        for industry in industries:

            pattern = rf"\b{re.escape(industry)}\b"

            if re.search(
                pattern,
                query,
            ):

                if industry in {
                    "health",
                }:
                    return "Healthcare"

                if industry in {
                    "financial",
                    "banking",
                }:
                    return "Finance"

                if industry == "it":
                    return "IT"

                return industry.title()

        return None

    def extract_attack_id(
        self,
        query: str,
    ) -> str | None:

        match = re.search(
            r"\bT\d{4}(?:\.\d{1,3})?\b",
            query.upper(),
        )

        if match:
            return match.group(0)

        return None

    def extract_malware(
        self,
        query: str,
    ) -> str | None:

        known_malware = [
            "medusa",
            "play",
            "ransomhub",
            "lockbit",
            "qilin",
            "interlock",
            "agenda",
            "coroxy",
            "grixba",
            "systembc",
            "underground ransomware",
        ]

        for malware in sorted(
            known_malware,
            key=len,
            reverse=True,
        ):

            if malware in query:

                return malware.title()

        return None

    def parse(
        self,
        query: str,
    ) -> dict[str, Any]:

        if not query or not query.strip():
            raise ValueError(
                "Query cannot be empty."
            )

        normalized_query = self.normalize_query(
            query
        )

        return {
        "original_query": query.strip(),
        "threat_type": self.extract_threat_type(
            normalized_query
        ),
        "country": self.extract_country(
            normalized_query
        ),
        "region": self.extract_region(
            normalized_query
        ),
        "industry": self.extract_industry(
            normalized_query
        ),
        "malware": self.extract_malware(
            normalized_query
        ),
        "attack_id": self.extract_attack_id(
            normalized_query
        ),
    }

    def extract_region(
        self,
        query: str,
    ) -> str | None:

        for region in sorted(
            self.REGIONS,
            key=len,
            reverse=True,
        ):

            pattern = rf"\b{re.escape(region.lower())}\b"

            if re.search(
                pattern,
                query,
            ):

                return region

        return None