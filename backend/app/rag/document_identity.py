"""Stable source-record and chunk identity helpers for retrieval."""

from __future__ import annotations

import hashlib

from langchain_core.documents import Document


def get_source_record_id(document: Document) -> str:
    """Return the source-level ID, separate from a retrieved chunk ID."""
    metadata = document.metadata
    for key in ("source_record_id", "record_id", "pulse_id", "id"):
        value = metadata.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()

    source = str(metadata.get("source", "")).strip()
    row = metadata.get("source_row")
    if source and row is not None:
        return f"{source}:row:{row}"

    title = str(metadata.get("title", "")).strip()
    if title:
        return title
    return "record:" + hashlib.sha256(
        document.page_content.encode("utf-8")
    ).hexdigest()


def get_chunk_id(document: Document) -> str:
    """Return a persisted chunk ID or a stable legacy fallback.

    The fallback includes the source record and content digest, so distinct
    chunks belonging to the same Pulse ID remain distinct retrieval results.
    """
    value = document.metadata.get("chunk_id")
    if value is not None and str(value).strip():
        return str(value).strip()
    digest = hashlib.sha256(
        document.page_content.encode("utf-8")
    ).hexdigest()[:20]
    return f"{get_source_record_id(document)}:chunk:{digest}"
