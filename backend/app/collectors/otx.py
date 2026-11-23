
from typing import Any, Optional

import requests

from app.collectors.base_collector import BaseCollector


OTX_API_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"


class OTXCollector(BaseCollector):
    """Collect subscribed threat intelligence pulses from AlienVault OTX."""

    def __init__(
        self,
        api_key: str,
        modified_since: Optional[str] = None,
        max_records: Optional[int] = None,
    ):
        super().__init__("OTX")

        if not api_key:
            raise ValueError("An AlienVault OTX API key is required.")

        self.api_key = api_key
        self.modified_since = modified_since
        self.max_records = max_records

        self.session = requests.Session()
        self.session.headers.update({
            "X-OTX-API-KEY": api_key
        })

    def fetch(self) -> list[dict[str, Any]]:
        """Fetch OTX pulses, following pagination links."""

        params = {}

        if self.modified_since:
            params["modified_since"] = self.modified_since

        next_url = OTX_API_URL
        pulses = []

        while next_url:
            response = self.session.get(
                next_url,
                params=params if next_url == OTX_API_URL else None,
                timeout=30,
            )
            response.raise_for_status()

            data = response.json()
            page_results = data.get("results", [])

            if not isinstance(page_results, list):
                raise ValueError("Unexpected OTX API response format.")

            for pulse in page_results:
                pulses.append(pulse)

                if (
                    self.max_records is not None
                    and len(pulses) >= self.max_records
                ):
                    return pulses

            next_url = data.get("next")

        return pulses


def fetch_otx(api_key: str):
    """Backward-compatible function for existing project code."""

    collector = OTXCollector(
        api_key=api_key,
        modified_since="2025-01-01T00:00:00",
    )

    return collector.fetch()
