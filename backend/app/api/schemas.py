"""Validated, client-safe response contracts for the GeoRAG API."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class QueryRequest(BaseModel):
    query: str = Field(min_length=1, max_length=4000, description="Natural-language CTI query")

    @field_validator("query")
    @classmethod
    def query_must_contain_text(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Query cannot be blank.")
        return value


class SourceDocument(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rank: int
    title: str
    source_record_id: str
    chunk_id: str
    similarity_score: float
    retrieval_score_semantics: str
    countries: Any = None
    country_associations: Any = None
    malware_families: Any = None
    industries: Any = None
    attack_ids: Any = None
    attack_techniques: list[dict[str, Any]] = Field(default_factory=list)
    excerpt: str = ""
    provenance: dict[str, Any] = Field(default_factory=dict)
    geographic_evidence: list[dict[str, Any]] = Field(default_factory=list)


class QueryResponse(BaseModel):
    """Phase 6 fields plus the Phase 0-compatible query/answer/sources keys."""

    query: str
    answer: str
    sources: list[SourceDocument]
    geographic_findings: dict[str, Any] = Field(default_factory=dict)
    threat_correlations: list[dict[str, Any]] = Field(default_factory=list)
    contextual_priorities: list[dict[str, Any]] = Field(default_factory=list)
    execution_plan: dict[str, Any] = Field(default_factory=dict)
    agent_results: dict[str, Any] = Field(default_factory=dict)
    execution_trace: dict[str, Any] = Field(default_factory=dict)
    warnings: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    partial: bool = False


class HealthResponse(BaseModel):
    status: str
    service: str


class ReadinessResponse(BaseModel):
    status: str
    pipeline_initialized: bool
