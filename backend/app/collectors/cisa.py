
from typing import Any

import requests

from app.collectors.base_collector import BaseCollector


CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


class CISAKevCollector(BaseCollector):
    """Collect Known Exploited Vulnerabilities from CISA."""

    def __init__(self):
        super().__init__("CISA_KEV")
        self.session = requests.Session()

    def fetch(self) -> list[dict[str, Any]]:
        """Fetch vulnerability records from the official CISA KEV feed."""

        response = self.session.get(
            CISA_KEV_URL,
            timeout=30,
        )
        response.raise_for_status()

        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])

        return vulnerabilities


def fetch_cisa_kev():
    """Backward-compatible function for existing project code."""

    collector = CISAKevCollector()
    return collector.fetch()
