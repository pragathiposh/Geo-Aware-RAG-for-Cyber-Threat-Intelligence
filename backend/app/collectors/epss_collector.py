"""Collector for the Exploit Prediction Scoring System (EPSS)."""

from typing import Any

import requests

from app.collectors.base_collector import BaseCollector


EPSS_API_URL = "https://api.first.org/data/v1/epss"


class EPSSCollector(BaseCollector):
    """Retrieve EPSS scores for selected CVE identifiers."""

    def __init__(self, cve_ids: list[str]):
        super().__init__("EPSS")
        self.cve_ids = list(dict.fromkeys(cve_ids))
        self.session = requests.Session()

    def fetch(self) -> list[dict[str, Any]]:
        """Fetch EPSS probabilities and percentiles."""

        if not self.cve_ids:
            return []

        results = []
        batch = []
        batch_length = 0

        # FIRST limits the CVE query parameter to 2000 characters.
        for cve_id in self.cve_ids:
            cve_id = cve_id.strip().upper()

            if not cve_id:
                continue

            additional_length = len(cve_id) + (1 if batch else 0)

            if batch and batch_length + additional_length > 1900:
                results.extend(self._fetch_batch(batch))
                batch = []
                batch_length = 0

            batch.append(cve_id)
            batch_length += len(cve_id) + (1 if len(batch) > 1 else 0)

        if batch:
            results.extend(self._fetch_batch(batch))

        return results

    def _fetch_batch(self, cve_ids: list[str]) -> list[dict[str, Any]]:
        response = self.session.get(
            EPSS_API_URL,
            params={"cve": ",".join(cve_ids)},
            timeout=30,
        )
        response.raise_for_status()

        data = response.json()

        if data.get("status") != "OK":
            raise ValueError("Unexpected response from FIRST EPSS API.")

        return [
            {
                "cve": record["cve"],
                "epss": float(record["epss"]),
                "percentile": float(record["percentile"]),
                "date": record.get("date"),
                "source": "FIRST_EPSS",
            }
            for record in data.get("data", [])
        ]


def fetch_epss(cve_ids: list[str]) -> list[dict[str, Any]]:
    """Convenience function for retrieving EPSS scores."""
    return EPSSCollector(cve_ids).fetch()
