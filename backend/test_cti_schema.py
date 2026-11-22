from app.threat_analysis.cti_mapper import CTIRecordMapper


def test_cti_record_mapping():
    metadata = {
        "pulse_id": "test-001",
        "title": "Example Ransomware Campaign",
        "author": "Test Analyst",
        "created": "2025-01-01T10:00:00",
        "modified": "2025-01-02T10:00:00",
        "tlp": "WHITE",
        "tags": "ransomware,malware",
        "malware_families": "LockBit,Play",
        "attack_ids": "T1486,T1190",
        "industries": "Healthcare,Finance",
        "countries": "United States,Canada",
        "source": "OTX",
    }

    record = CTIRecordMapper.from_metadata(
        metadata=metadata,
        description="Example ransomware intelligence.",
    )

    assert record.record_id == "test-001"

    assert record.title == "Example Ransomware Campaign"

    assert "United States" in record.geography.countries

    assert "Canada" in record.geography.countries

    assert "Healthcare" in record.targets.industries

    assert len(record.malware) == 2

    assert record.malware[0].name == "LockBit"

    assert len(record.attack_techniques) == 2

    assert record.attack_techniques[0].attack_id == "T1486"