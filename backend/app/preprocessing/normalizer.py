"""Normalize collected threat-intelligence records."""

"""Normalize collected threat-intelligence records."""

from typing import Any


def normalize_nvd(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize an NVD vulnerability record."""

    cve = record.get("cve", record)

    descriptions = cve.get("descriptions", [])
    english_description = next(
        (
            item.get("value", "")
            for item in descriptions
            if item.get("lang") == "en"
        ),
        "",
    )

    cvss_score = None
    cvss_severity = None

    metrics = cve.get("metrics", {})

    for version in (
        "cvssMetricV40",
        "cvssMetricV31",
        "cvssMetricV30",
        "cvssMetricV2",
    ):
        metric_records = metrics.get(version, [])

        if metric_records:
            selected = next(
                (
                    item
                    for item in metric_records
                    if item.get("type") == "Primary"
                ),
                metric_records[0],
            )

            cvss_data = selected.get("cvssData", {})
            cvss_score = cvss_data.get("baseScore")
            cvss_severity = (
                cvss_data.get("baseSeverity")
                or selected.get("baseSeverity")
            )
            break

    return {
        "id": cve.get("id"),
        "source": "NVD",
        "record_type": "vulnerability",
        "title": cve.get("id", ""),
        "description": english_description,
        "cve_id": cve.get("id"),
        "cvss_score": cvss_score,
        "cvss_severity": cvss_severity,
        "published_at": cve.get("published"),
        "modified_at": cve.get("lastModified"),
    }


def normalize_cisa(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize a CISA KEV record."""

    cve_id = record.get("cveID")

    return {
        "id": f"CISA-KEV:{cve_id}" if cve_id else None,
        "source": "CISA_KEV",
        "record_type": "known_exploited_vulnerability",
        "title": record.get("vulnerabilityName", ""),
        "description": record.get("shortDescription", ""),
        "cve_id": cve_id,
        "vendor": record.get("vendorProject"),
        "product": record.get("product"),
        "known_exploited": True,
        "date_added": record.get("dateAdded"),
        "due_date": record.get("dueDate"),
        "required_action": record.get("requiredAction"),
        "known_ransomware_campaign_use": record.get(
            "knownRansomwareCampaignUse"
        ),
    }


def normalize_otx(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize an AlienVault OTX pulse."""

    pulse_id = record.get("id")

    indicators = record.get("indicators", [])
    if not isinstance(indicators, list):
        indicators = []

    return {
        "id": f"OTX:{pulse_id}" if pulse_id else None,
        "source": "OTX",
        "record_type": "threat_intelligence_pulse",
        "title": record.get("name", ""),
        "description": record.get("description", ""),
        "pulse_id": pulse_id,
        "tags": record.get("tags", []),
        "attack_ids": record.get("attack_ids", []),
        "malware_families": record.get("malware_families", []),
        "indicator_count": len(indicators),
        "published_at": record.get("created"),
        "modified_at": record.get("modified"),
    }


def normalize_epss(record: dict[str, Any]) -> dict[str, Any]:
    """Normalize a FIRST EPSS score record."""

    cve_id = record.get("cve")

    return {
        "id": f"EPSS:{cve_id}" if cve_id else None,
        "source": "FIRST_EPSS",
        "record_type": "exploit_probability",
        "title": f"EPSS score for {cve_id}" if cve_id else "",
        "description": "FIRST EPSS exploitation probability estimate.",
        "cve_id": cve_id,
        "epss_score": (
            float(record["epss"])
            if record.get("epss") is not None
            else None
        ),
        "epss_percentile": (
            float(record["percentile"])
            if record.get("percentile") is not None
            else None
        ),
        "score_date": record.get("date"),
    }


def normalize_record(
    source: str,
    record: dict[str, Any],
) -> dict[str, Any]:
    """Dispatch a record to the appropriate normalizer."""

    normalizers = {
        "NVD": normalize_nvd,
        "CISA_KEV": normalize_cisa,
        "OTX": normalize_otx,
        "EPSS": normalize_epss,
        "FIRST_EPSS": normalize_epss,
    }

    source_key = source.upper()

    if source_key not in normalizers:
        raise ValueError(f"Unsupported CTI source: {source}")

    return normalizers[source_key](record)
