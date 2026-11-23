"""Build processed and training datasets from threat-intelligence records."""

"""Build enriched CVE datasets from normalized CTI records."""

from typing import Any


def build_cve_dataset(
    nvd_records: list[dict[str, Any]],
    cisa_records: list[dict[str, Any]],
    epss_records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Merge normalized records using their CVE identifiers."""

    merged: dict[str, dict[str, Any]] = {}

    def get_or_create(cve_id: str) -> dict[str, Any]:
        cve_id = cve_id.strip().upper()

        if cve_id not in merged:
            merged[cve_id] = {
                "cve_id": cve_id,
                "title": None,
                "description": None,
                "cvss_score": None,
                "cvss_severity": None,
                "known_exploited": False,
                "epss_score": None,
                "epss_percentile": None,
                "epss_date": None,
                "published_at": None,
                "modified_at": None,
                "cisa_date_added": None,
                "sources": [],
            }

        return merged[cve_id]

    for record in nvd_records:
        cve_id = record.get("cve_id")

        if not cve_id:
            continue

        entry = get_or_create(cve_id)
        entry["title"] = record.get("title")
        entry["description"] = record.get("description")
        entry["cvss_score"] = record.get("cvss_score")
        entry["cvss_severity"] = record.get("cvss_severity")
        entry["published_at"] = record.get("published_at")
        entry["modified_at"] = record.get("modified_at")

        if "NVD" not in entry["sources"]:
            entry["sources"].append("NVD")

    for record in cisa_records:
        cve_id = record.get("cve_id")

        if not cve_id:
            continue

        entry = get_or_create(cve_id)

        if not entry["title"]:
            entry["title"] = record.get("title")

        if not entry["description"]:
            entry["description"] = record.get("description")

        entry["known_exploited"] = True
        entry["cisa_date_added"] = record.get("date_added")

        if "CISA_KEV" not in entry["sources"]:
            entry["sources"].append("CISA_KEV")

    for record in epss_records:
        cve_id = record.get("cve_id")

        if not cve_id:
            continue

        entry = get_or_create(cve_id)
        entry["epss_score"] = record.get("epss_score")
        entry["epss_percentile"] = record.get("epss_percentile")
        entry["epss_date"] = record.get("score_date")

        if "FIRST_EPSS" not in entry["sources"]:
            entry["sources"].append("FIRST_EPSS")

    return list(merged.values())
