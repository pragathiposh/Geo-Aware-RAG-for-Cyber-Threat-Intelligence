
import time
from typing import Any, Optional

import requests

from app.collectors.base_collector import BaseCollector


NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class NVDCollector(BaseCollector):
    """Collect CVE records from the National Vulnerability Database."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        results_per_page: int = 2000,
        max_records: Optional[int] = None,
        delay_seconds: float = 6.5,
    ):
        super().__init__("NVD")

        if not 1 <= results_per_page <= 2000:
            raise ValueError("results_per_page must be between 1 and 2000.")

        self.api_key = api_key
        self.results_per_page = results_per_page
        self.max_records = max_records
        self.delay_seconds = delay_seconds

        self.session = requests.Session()

        if api_key:
            self.session.headers.update({"apiKey": api_key})

    def fetch(self) -> list[dict[str, Any]]:
        """Fetch CVE records from NVD, using pagination."""

        vulnerabilities = []
        start_index = 0
        total_results = None

        while total_results is None or start_index < total_results:

            if self.max_records is not None:
                remaining = self.max_records - len(vulnerabilities)

                if remaining <= 0:
                    break

                page_size = min(self.results_per_page, remaining)
            else:
                page_size = self.results_per_page

            params = {
                "resultsPerPage": page_size,
                "startIndex": start_index,
            }

            response = self.session.get(
                NVD_API_URL,
                params=params,
                timeout=30,
            )
            response.raise_for_status()

            data = response.json()

            total_results = data.get("totalResults", 0)
            page_records = data.get("vulnerabilities", [])

            if not page_records:
                break

            vulnerabilities.extend(page_records)
            start_index += len(page_records)

            if start_index < total_results:
                time.sleep(self.delay_seconds)

        return vulnerabilities


def fetch_nvd(api_key: Optional[str] = None):
    """
    Backward-compatible function for existing code.
    Fetches the first 2000 NVD records.
    """
    collector = NVDCollector(
        api_key=api_key,
        max_records=2000,
    )
    return collector.fetch()
