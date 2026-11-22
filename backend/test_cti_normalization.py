from app.threat_analysis.cti_mapper import CTIRecordMapper
from app.threat_analysis.normalization import CTINormalizer


def test_country_normalization():

    assert (
        CTINormalizer.normalize_country(
            "United States of America"
        )
        == "United States"
    )

    assert (
        CTINormalizer.normalize_country(
            "USA"
        )
        == "United States"
    )

    assert (
        CTINormalizer.normalize_country(
            "US"
        )
        == "United States"
    )


def test_unknown_country_is_removed():

    assert (
        CTINormalizer.normalize_country(
            "Unknown"
        )
        is None
    )


def test_industry_normalization():

    assert (
        CTINormalizer.normalize_industry(
            "health"
        )
        == "Healthcare"
    )

    assert (
        CTINormalizer.normalize_industry(
            "financial services"
        )
        == "Finance"
    )

    assert (
        CTINormalizer.normalize_industry(
            "IT"
        )
        == "Technology"
    )


def test_attack_id_normalization():

    assert (
        CTINormalizer.normalize_attack_id(
            "t1486"
        )
        == "T1486"
    )

    assert (
        CTINormalizer.normalize_attack_id(
            "T1059.001"
        )
        == "T1059.001"
    )

    assert (
        CTINormalizer.normalize_attack_id(
            "invalid"
        )
        is None
    )


def test_record_normalization():

    metadata = {
        "pulse_id": "test-normalization",
        "title": "Test Threat",
        "countries": "USA, United States of America",
        "industries": "health, financial services",
        "malware_families": "ExampleMalware",
        "attack_ids": "t1486,t1059.001",
        "tags": " ransomware , malware ",
    }

    record = CTIRecordMapper.from_metadata(
        metadata=metadata,
        description="Example CTI record.",
    )

    normalized = CTINormalizer.normalize_record(
        record
    )

    assert normalized.geography.countries == [
        "United States"
    ]

    assert normalized.targets.industries == [
        "Finance",
        "Healthcare",
    ]

    attack_ids = {
        technique.attack_id
        for technique in normalized.attack_techniques
    }

    assert attack_ids == {
        "T1486",
        "T1059.001",
    }

    assert normalized.tags == [
        "malware",
        "ransomware",
    ]

def test_unknown_malware_is_removed():

    metadata = {
        "pulse_id": "test-malware",
        "title": "Unknown Malware Test",
        "countries": "United States",
        "industries": "Technology",
        "malware_families": "Unknown",
        "attack_ids": "T1486",
    }

    record = CTIRecordMapper.from_metadata(
        metadata=metadata,
        description="Test record.",
    )

    normalized = CTINormalizer.normalize_record(
        record
    )

    assert normalized.malware == []

def test_united_kingdom_long_name_normalization():

    assert (
        CTINormalizer.normalize_country(
            "United Kingdom of Great Britain and Northern Ireland"
        )
        == "United Kingdom"
    )