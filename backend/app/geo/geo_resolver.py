from typing import Any


class GeoResolver:
    """
    Geographic entity resolver for the Geo-Aware CTI system.

    Responsibilities:
        1. Normalize country aliases.
        2. Resolve countries to canonical names.
        3. Map countries to regions.
        4. Map countries to continents.

    This is the first version of the geographic
    intelligence layer.
    """

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
        "great britain": "United Kingdom",

        "uae": "United Arab Emirates",
        "u.a.e.": "United Arab Emirates",

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
        "north korea": "North Korea", "south korea": "South Korea",
        "russia": "Russia", "russian federation": "Russia", "ukraine": "Ukraine",
        "brazil": "Brazil", "mexico": "Mexico", "vietnam": "Vietnam",
        "azerbaijan": "Azerbaijan", "mongolia": "Mongolia", "finland": "Finland",
        "pakistan": "Pakistan", "indonesia": "Indonesia", "philippines": "Philippines",
        "poland": "Poland", "netherlands": "Netherlands", "sweden": "Sweden",
        "norway": "Norway", "belgium": "Belgium", "italy": "Italy", "ireland": "Ireland",
        "afghanistan": "Afghanistan", "argentina": "Argentina", "colombia": "Colombia",
        "chile": "Chile", "turkey": "Türkiye", "türkiye": "Türkiye",
    }

    COUNTRY_REGIONS = {
        "United States": "North America",
        "Canada": "North America",
        "Mexico": "North America",

        "United Kingdom": "Europe",
        "Germany": "Europe",
        "France": "Europe",
        "Portugal": "Europe",
        "Croatia": "Europe",
        "Spain": "Europe",
        "Slovakia": "Europe",
        "Finland": "Europe", "Poland": "Europe", "Netherlands": "Europe",
        "Sweden": "Europe", "Norway": "Europe", "Belgium": "Europe",
        "Italy": "Europe", "Ireland": "Europe", "Russia": "Europe",

        "India": "South Asia",
        "Pakistan": "South Asia", "Afghanistan": "South Asia",

        "China": "East Asia",
        "Japan": "East Asia",
        "Taiwan": "East Asia",
        "Singapore": "Southeast Asia",

        "Australia": "Oceania",

        "Israel": "Middle East",
        "Iran": "Middle East",
        "United Arab Emirates": "Middle East",

        "Thailand": "Southeast Asia",
        "Vietnam": "Southeast Asia", "Indonesia": "Southeast Asia",
        "Philippines": "Southeast Asia",
        "North Korea": "East Asia", "South Korea": "East Asia", "Mongolia": "East Asia",
        "Brazil": "South America", "Argentina": "South America", "Colombia": "South America", "Chile": "South America",
        "Azerbaijan": "Middle East", "Türkiye": "Middle East",
    }

    REGION_CONTINENTS = {
        "North America": "North America",
        "Europe": "Europe",
        "South Asia": "Asia",
        "East Asia": "Asia",
        "Southeast Asia": "Asia",
        "Middle East": "Asia",
        "Oceania": "Oceania",
    }

    REGION_COUNTRIES = {
        "North America": [
            "United States",
            "Canada",
            "Mexico",
        ],

        "Europe": [
            "United Kingdom",
            "Germany",
            "France",
            "Portugal",
            "Croatia",
            "Spain",
            "Slovakia",
            "Finland", "Poland", "Netherlands", "Sweden", "Norway", "Belgium", "Italy", "Ireland", "Russia",
        ],

        "South Asia": [
            "India",
            "Pakistan", "Afghanistan",
        ],

        "East Asia": [
            "China",
            "Japan",
            "Taiwan",
            "North Korea", "South Korea", "Mongolia",
        ],

        "Southeast Asia": [
            "Singapore",
            "Thailand",
            "Vietnam", "Indonesia", "Philippines",
        ],

        "Middle East": [
            "Israel",
            "Iran",
            "United Arab Emirates",
        ],

        "Oceania": [
            "Australia",
        ],

        "South America": ["Brazil", "Argentina", "Colombia", "Chile"],
        "Central America": [],
        "Africa": [],
    }

    @classmethod
    def normalize_country(
        cls,
        country: str,
    ) -> str | None:
        """
        Convert a country alias into a canonical country name.
        """

        if not country or not country.strip():
            return None

        normalized = country.strip().lower()

        return cls.COUNTRY_ALIASES.get(
            normalized
        )

    @classmethod
    def get_region(
        cls,
        country: str,
    ) -> str | None:
        """
        Return the geographic region for a country.
        """

        canonical_country = cls.normalize_country(
            country
        )

        if canonical_country is None:
            return None

        return cls.COUNTRY_REGIONS.get(
            canonical_country
        )

    @classmethod
    def get_continent(
        cls,
        country: str,
    ) -> str | None:
        """
        Return the continent for a country.
        """

        region = cls.get_region(
            country
        )

        if region is None:
            return None

        return cls.REGION_CONTINENTS.get(
            region
        )

    @classmethod
    def resolve(
        cls,
        country: str,
    ) -> dict[str, Any]:
        """
        Resolve a country into a structured geographic entity.
        """

        canonical_country = cls.normalize_country(
            country
        )

        if canonical_country is None:
            return {
                "input": country,
                "country": None,
                "region": None,
                "continent": None,
            }

        region = cls.COUNTRY_REGIONS.get(
            canonical_country
        )

        continent = None

        if region:
            continent = cls.REGION_CONTINENTS.get(
                region
            )

        return {
            "input": country,
            "country": canonical_country,
            "region": region,
            "continent": continent,
        }

    @classmethod
    def resolve_region(
        cls,
        region: str,
    ) -> dict[str, Any]:
        """
        Resolve a region into its constituent countries
        and continent.
        """

        if not region or not region.strip():
            return {
                "input": region,
                "region": None,
                "continent": None,
                "countries": [],
            }

        normalized = region.strip().lower()

        matched_region = None

        for known_region in cls.REGION_COUNTRIES:
            if known_region.lower() == normalized:
                matched_region = known_region
                break

        if matched_region is None:
            return {
                "input": region,
                "region": None,
                "continent": None,
                "countries": [],
            }

        continent = cls.REGION_CONTINENTS.get(
            matched_region
        )

        countries = cls.REGION_COUNTRIES.get(
            matched_region,
            [],
        )

        return {
            "input": region,
            "region": matched_region,
            "continent": continent,
            "countries": countries,
        }
