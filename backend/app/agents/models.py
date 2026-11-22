"""Structured contracts shared by the CTI agents and orchestrator."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from app.threat_analysis.priority import PriorityContext


class AgentStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class QueryIntents(BaseModel):
    geographic: bool = False
    correlation: bool = False
    contextual_risk: bool = False


class AgentExecutionPlan(BaseModel):
    query: str
    parsed_entities: dict[str, Any] = Field(default_factory=dict)
    intents: QueryIntents = Field(default_factory=QueryIntents)
    selected_agents: list[str]
    selection_reasons: dict[str, str] = Field(default_factory=dict)
    metadata_filters: dict[str, str] = Field(default_factory=dict)
    priority_context: PriorityContext = Field(default_factory=PriorityContext)


class AgentEvidenceReference(BaseModel):
    source_record_id: str
    chunk_id: str | None = None
    title: str | None = None
    excerpt: str = ""
    provenance: dict[str, Any] = Field(default_factory=dict)
    retrieval_score: float | None = None
    retrieval_score_semantics: str | None = None


class AgentResult(BaseModel):
    agent_name: str
    status: AgentStatus
    input_summary: dict[str, Any] = Field(default_factory=dict)
    output_data: dict[str, Any] = Field(default_factory=dict)
    evidence_references: list[AgentEvidenceReference] = Field(default_factory=list)
    source_record_ids: list[str] = Field(default_factory=list)
    # Reserved for calibrated agent-level confidence. Retrieval relevance,
    # correlation evidence strength, and priority remain in separate fields.
    confidence: float | None = Field(default=None, ge=0, le=1)
    confidence_semantics: str | None = None
    missing_information: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    execution_duration_ms: float = 0.0
    error: str | None = None


class AgentInput(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    query: str
    plan: AgentExecutionPlan
    retrieved_documents: list[Any] = Field(default_factory=list)
    upstream_results: dict[str, AgentResult] = Field(default_factory=dict)


class AgentExecution(BaseModel):
    """Serializable agent result plus internal artifacts excluded from traces."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    result: AgentResult
    artifacts: dict[str, Any] = Field(default_factory=dict, exclude=True)


class AgentTraceEntry(BaseModel):
    agent_name: str
    selected: bool
    reason: str
    status: AgentStatus
    source_record_ids: list[str] = Field(default_factory=list)
    missing_information: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    execution_duration_ms: float = 0.0
    error: str | None = None


class ExecutionTrace(BaseModel):
    plan: AgentExecutionPlan
    entries: list[AgentTraceEntry]
    total_execution_duration_ms: float
    partial_execution: bool = False
    warnings: list[str] = Field(default_factory=list)
