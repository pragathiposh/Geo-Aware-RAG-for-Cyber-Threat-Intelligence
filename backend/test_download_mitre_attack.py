import json
from datetime import datetime, timezone
from pathlib import Path
import pytest

from download_mitre_attack import (
    DATASET_VERSION,
    SOURCE_REF,
    SOURCE_URL,
    MIN_ENTERPRISE_ATTACK_PATTERNS,
    DatasetValidationError,
    bootstrap_dataset,
    validate_bundle_bytes,
)


def bundle_bytes(*, attack_patterns=MIN_ENTERPRISE_ATTACK_PATTERNS, spec_version=None):
    objects = [{"type": "identity", "id": "identity--org"}]
    for index in range(attack_patterns):
        objects.append({
            "type": "attack-pattern",
            "id": f"attack-pattern--technique-{index}",
            "x_mitre_domains": ["enterprise-attack"],
            "external_references": [{"source_name": "mitre-attack", "external_id": f"T{index + 1}"}],
        })
    bundle = {"type": "bundle", "id": "bundle--test", "objects": objects}
    if spec_version is not None:
        bundle["spec_version"] = spec_version
    return json.dumps(bundle).encode()


class FakeResponse:
    def __init__(self, payload):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self.payload


def test_download_pinned_bundle_validates_and_writes_manifest(tmp_path):
    destination = tmp_path / "data" / "mitre" / "enterprise-attack.json"
    requested = {}

    def fake_open(request, timeout):
        requested["url"] = request.full_url
        requested["timeout"] = timeout
        return FakeResponse(bundle_bytes())

    timestamp = datetime(2026, 11, 22, 9, 0, tzinfo=timezone.utc)
    result = bootstrap_dataset(destination, opener=fake_open, downloaded_at=timestamp)

    assert requested["url"] == SOURCE_URL
    assert SOURCE_REF == "ATT&CK-v20.1"
    assert DATASET_VERSION == "20.1"
    assert result["status"] == "downloaded"
    assert destination.read_bytes() == bundle_bytes()
    manifest = json.loads(Path(result["manifest"]).read_text(encoding="utf-8"))
    assert manifest["version"] == "20.1"
    assert manifest["source_ref"] == "ATT&CK-v20.1"
    assert manifest["stix_spec_version"] == "2.0"
    assert manifest["downloaded_at_utc"] == "2026-11-22T09:00:00Z"
    assert manifest["enterprise_attack_pattern_count"] == MIN_ENTERPRISE_ATTACK_PATTERNS


def test_valid_existing_dataset_is_not_downloaded_or_overwritten(tmp_path):
    destination = tmp_path / "enterprise-attack.json"
    original = bundle_bytes()
    destination.write_bytes(original)

    def should_not_open(*_args, **_kwargs):
        raise AssertionError("existing valid data should be reused")

    result = bootstrap_dataset(destination, opener=should_not_open)

    assert result["status"] == "already_present"
    assert destination.read_bytes() == original


@pytest.mark.parametrize(
    "payload",
    [b"{truncated", bundle_bytes(attack_patterns=1), bundle_bytes(spec_version="3.0"), b"[]"],
    ids=["invalid_json", "incomplete_bundle", "invalid_spec_version", "invalid_root"],
)
def test_invalid_download_is_rejected_without_replacing_existing_data(tmp_path, payload):
    destination = tmp_path / "enterprise-attack.json"
    original = bundle_bytes()
    destination.write_bytes(original)

    with pytest.raises(DatasetValidationError):
        bootstrap_dataset(destination, force=True, opener=lambda *_args, **_kwargs: FakeResponse(payload))

    assert destination.read_bytes() == original
    assert list(tmp_path.glob("*.tmp")) == []


def test_invalid_existing_dataset_is_preserved_without_force(tmp_path):
    destination = tmp_path / "enterprise-attack.json"
    original = b"preserve me"
    destination.write_bytes(original)

    with pytest.raises(DatasetValidationError, match="left untouched"):
        bootstrap_dataset(destination, opener=lambda *_args, **_kwargs: FakeResponse(bundle_bytes()))

    assert destination.read_bytes() == original


def test_valid_stix_20_bundle_has_enterprise_pattern():
    assert validate_bundle_bytes(bundle_bytes())["type"] == "bundle"


def test_valid_stix_21_bundle_is_also_supported():
    assert validate_bundle_bytes(bundle_bytes(spec_version="2.1"))["spec_version"] == "2.1"


def test_network_failure_does_not_create_dataset_or_temp_files(tmp_path):
    destination = tmp_path / "enterprise-attack.json"

    def fail_network(*_args, **_kwargs):
        raise OSError("offline")

    with pytest.raises(OSError, match="offline"):
        bootstrap_dataset(destination, opener=fail_network)

    assert not destination.exists()
    assert list(tmp_path.glob("*.tmp")) == []


def test_force_refresh_replaces_only_after_valid_download(tmp_path):
    destination = tmp_path / "enterprise-attack.json"
    old_bytes = bundle_bytes()
    new_bundle = json.loads(bundle_bytes())
    new_bundle["objects"].append({"type": "note", "id": "note--refreshed"})
    new_bytes = json.dumps(new_bundle).encode()
    destination.write_bytes(old_bytes)

    result = bootstrap_dataset(
        destination,
        force=True,
        opener=lambda *_args, **_kwargs: FakeResponse(new_bytes),
    )

    assert result["status"] == "downloaded"
    assert destination.read_bytes() == new_bytes
    assert Path(result["manifest"]).is_file()
