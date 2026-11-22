"""Small, reusable retrieval metrics for positive-labeled CTI queries."""

from __future__ import annotations

import math


def recall_at_k(ranked_ids: list[str], relevant_ids: set[str], k: int = 5) -> float:
    if k <= 0 or not relevant_ids:
        return 0.0
    return len(set(ranked_ids[:k]) & relevant_ids) / len(relevant_ids)


def mean_reciprocal_rank(ranked_ids: list[str], relevant_ids: set[str]) -> float:
    for rank, source_id in enumerate(ranked_ids, start=1):
        if source_id in relevant_ids:
            return 1.0 / rank
    return 0.0


def ndcg_at_k(ranked_ids: list[str], relevant_ids: set[str], k: int = 5) -> float:
    if k <= 0 or not relevant_ids:
        return 0.0
    dcg = sum(
        1.0 / math.log2(rank + 1)
        for rank, source_id in enumerate(ranked_ids[:k], start=1)
        if source_id in relevant_ids
    )
    ideal_relevant = min(len(relevant_ids), k)
    ideal = sum(1.0 / math.log2(rank + 1) for rank in range(1, ideal_relevant + 1))
    return dcg / ideal if ideal else 0.0


def ranked_source_ids(documents) -> list[str]:
    """Collapse sibling chunks to their first ranked source record."""
    ranked: list[str] = []
    seen: set[str] = set()
    for document in documents:
        metadata = document.metadata
        source_id = (
            metadata.get("source_record_id")
            or metadata.get("record_id")
            or metadata.get("pulse_id")
            or metadata.get("source_row")
            or metadata.get("title")
        )
        if source_id is None:
            continue
        source_id = str(source_id)
        if source_id not in seen:
            seen.add(source_id)
            ranked.append(source_id)
    return ranked
