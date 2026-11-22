"""Download the pinned MITRE Enterprise ATT&CK STIX bundle.

Run from ``backend/``. The script uses only the Python standard library and
does not replace a valid local dataset unless ``--force`` is supplied.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.request import Request, urlopen


DATASET_VERSION = "20.1"
SOURCE_REF = "ATT&CK-v20.1"
SOURCE_REPOSITORY = "https://github.com/mitre/cti"
SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre/cti/"
    f"ATT%26CK-v{DATASET_VERSION}/enterprise-attack/enterprise-attack.json"
)
DEFAULT_DESTINATION = (
    Path(__file__).resolve().parent / "data" / "mitre" / "enterprise-attack.json"
)
MANIFEST_SUFFIX = ".manifest.json"
DOWNLOAD_TIMEOUT_SECONDS = 60
# Enterprise ATT&CK contains hundreds of techniques. A syntactically valid but
# truncated/small bundle must not be accepted as a full release.
MIN_ENTERPRISE_ATTACK_PATTERNS = 500


class DatasetValidationError(ValueError):
    """Raised when a downloaded ATT&CK file is not a usable STIX bundle."""


def validate_bundle_bytes(payload: bytes) -> dict[str, Any]:
    """Parse and validate the expected STIX bundle and Enterprise objects."""
    try:
        bundle = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DatasetValidationError("Downloaded data is not valid JSON.") from exc

    if not isinstance(bundle, dict) or bundle.get("type") != "bundle":
        raise DatasetValidationError("JSON root must be a STIX bundle object.")
    if not isinstance(bundle.get("id"), str) or not bundle["id"].startswith("bundle--"):
        raise DatasetValidationError("STIX bundle is missing a valid bundle ID.")
    # STIX 2.0 bundle serialization predates the spec_version field; the
    # project's MitreAttackData collector consumes this representation.
    spec_version = bundle.get("spec_version", "2.0")
    if spec_version not in {"2.0", "2.1"}:
        raise DatasetValidationError("STIX bundle spec_version must be 2.0 or 2.1 when present.")
    objects = bundle.get("objects")
    if not isinstance(objects, list) or not objects:
        raise DatasetValidationError("STIX bundle must contain a non-empty objects list.")

    enterprise_patterns = [
        obj for obj in objects
        if isinstance(obj, dict)
        and obj.get("type") == "attack-pattern"
        and (
            (isinstance(obj.get("x_mitre_domains"), list)
             and "enterprise-attack" in obj["x_mitre_domains"])
            or any(
                ref.get("source_name") == "mitre-attack"
                and isinstance(ref.get("external_id"), str)
                and ref["external_id"].startswith("T")
                for ref in obj.get("external_references", [])
                if isinstance(ref, dict)
            )
        )
    ]
    if len(enterprise_patterns) < MIN_ENTERPRISE_ATTACK_PATTERNS:
        raise DatasetValidationError(
            "STIX bundle is incomplete: expected at least "
            f"{MIN_ENTERPRISE_ATTACK_PATTERNS} Enterprise ATT&CK attack-pattern objects; "
            f"found {len(enterprise_patterns)}."
        )
    return bundle


def _load_existing_dataset(destination: Path) -> bool:
    """Return true for an existing valid dataset, without modifying it."""
    if not destination.exists():
        return False
    try:
        validate_bundle_bytes(destination.read_bytes())
    except OSError as exc:
        raise DatasetValidationError(f"Cannot read existing dataset: {destination}") from exc
    except DatasetValidationError as exc:
        raise DatasetValidationError(
            f"Existing dataset is invalid and was left untouched: {destination}. "
            "Use --force only to replace it with a validated download."
        ) from exc
    return True


def _write_temp_file(directory: Path, prefix: str, content: bytes) -> Path:
    handle, name = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=directory)
    path = Path(name)
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        path.unlink(missing_ok=True)
        raise
    return path


def bootstrap_dataset(
    destination: Path = DEFAULT_DESTINATION,
    *,
    force: bool = False,
    opener: Callable[..., Any] = urlopen,
    downloaded_at: datetime | None = None,
) -> dict[str, Any]:
    """Download, validate, and atomically install the pinned bundle."""
    destination = Path(destination)
    manifest_path = destination.with_name(destination.name + MANIFEST_SUFFIX)
    if _load_existing_dataset(destination) and not force:
        return {"status": "already_present", "path": str(destination)}

    destination.parent.mkdir(parents=True, exist_ok=True)
    request = Request(SOURCE_URL, headers={"User-Agent": "GeoRAG-CTI-dataset-bootstrap/1.0"})
    with opener(request, timeout=DOWNLOAD_TIMEOUT_SECONDS) as response:
        payload = response.read()
    bundle = validate_bundle_bytes(payload)
    timestamp = (downloaded_at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    manifest = {
        "dataset": "MITRE Enterprise ATT&CK STIX JSON",
        "version": DATASET_VERSION,
        "source_repository": SOURCE_REPOSITORY,
        "source_ref": SOURCE_REF,
        "source_url": SOURCE_URL,
        "downloaded_at_utc": timestamp.isoformat().replace("+00:00", "Z"),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "stix_spec_version": bundle.get("spec_version", "2.0"),
        "object_count": len(bundle["objects"]),
        "enterprise_attack_pattern_count": sum(
            1 for obj in bundle["objects"]
            if isinstance(obj, dict) and obj.get("type") == "attack-pattern"
            and isinstance(obj.get("x_mitre_domains"), list)
            and "enterprise-attack" in obj["x_mitre_domains"]
        ),
    }
    manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    dataset_temp: Path | None = None
    manifest_temp: Path | None = None
    try:
        # Both files are fully written before replacing either destination.
        dataset_temp = _write_temp_file(destination.parent, ".enterprise-attack-", payload)
        manifest_temp = _write_temp_file(destination.parent, ".enterprise-attack-manifest-", manifest_bytes)
        os.replace(dataset_temp, destination)
        dataset_temp = None
        os.replace(manifest_temp, manifest_path)
        manifest_temp = None
    finally:
        if dataset_temp is not None:
            dataset_temp.unlink(missing_ok=True)
        if manifest_temp is not None:
            manifest_temp.unlink(missing_ok=True)
    return {"status": "downloaded", "path": str(destination), "manifest": str(manifest_path), **manifest}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="Replace an existing valid dataset after validation")
    parser.add_argument("--destination", type=Path, default=DEFAULT_DESTINATION)
    args = parser.parse_args()
    result = bootstrap_dataset(args.destination, force=args.force)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
