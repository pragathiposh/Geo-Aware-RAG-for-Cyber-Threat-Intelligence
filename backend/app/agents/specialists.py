"""Reusable specialist agents backed by the existing Phase 2–4 services."""

from __future__ import annotations

import json
from time import perf_counter
from typing import Any

from app.agents.models import AgentExecution, AgentEvidenceReference, AgentInput, AgentResult, AgentStatus
from app.geo.geo_analysis import aggregate_geography, supported_location_evidence
from app.rag.document_identity import get_chunk_id, get_source_record_id
from app.threat_analysis.analysis_engine import ThreatAnalysisEngine


def _canonical_records(documents: list[Any]) -> list[dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for doc in documents:
        metadata = getattr(doc, "metadata", {}) or {}
        value = metadata.get("canonical_cti", {})
        if isinstance(value, str):
            try:
                value = json.loads(value)
            except (ValueError, TypeError):
                value = {}
        if not isinstance(value, dict):
            value = {}
        record_id = str(metadata.get("source_record_id") or value.get("record_id") or get_source_record_id(doc))
        if record_id not in records:
            records[record_id] = {**value, "record_id": record_id}
            # Keep metadata-backed evidence available to the Phase 3 helpers.
            records[record_id]["geographic_evidence"] = value.get("geographic_evidence", metadata.get("geographic_evidence", []))
            records[record_id]["geography"] = value.get("geography", {})
            records[record_id]["tags"] = value.get("tags", metadata.get("canonical_tags", metadata.get("tags", [])))
            records[record_id]["countries"] = metadata.get("countries", value.get("countries", []))
    return list(records.values())


class RetrievalAgent:
    def __init__(self, retriever: Any):
        self.retriever = retriever

    def run(self, agent_input: AgentInput, *, top_k: int) -> AgentExecution:
        started = perf_counter()
        filters = agent_input.plan.metadata_filters or None
        if filters:
            documents = self.retriever.retrieve(agent_input.query, top_k=top_k, filters=filters)
        else:
            documents = self.retriever.retrieve(agent_input.query, top_k=top_k)
        refs = []
        for doc, score in documents:
            metadata = doc.metadata or {}
            refs.append(AgentEvidenceReference(
                source_record_id=get_source_record_id(doc), chunk_id=get_chunk_id(doc),
                title=metadata.get("title"), excerpt=doc.page_content[:600],
                provenance={k: metadata[k] for k in ("source", "source_row", "pulse_id", "source_record_id") if k in metadata},
                retrieval_score=float(score), retrieval_score_semantics="cross-encoder relevance logit; not probability or factual confidence",
            ))
        result = AgentResult(
            agent_name="retrieval", status=AgentStatus.SUCCESS if documents else AgentStatus.PARTIAL,
            input_summary={"query": agent_input.query, "filters": agent_input.plan.metadata_filters},
            output_data={"count": len(documents), "ranked_chunks": [
                {"chunk_id": get_chunk_id(doc), "source_record_id": get_source_record_id(doc), "relevance_score": float(score)}
                for doc, score in documents
            ]}, evidence_references=refs,
            source_record_ids=list(dict.fromkeys(ref.source_record_id for ref in refs)),
            missing_information=[] if documents else ["No CTI documents matched the query."],
            execution_duration_ms=(perf_counter() - started) * 1000,
        )
        return AgentExecution(result=result, artifacts={"documents": documents})


class GeographicIntelligenceAgent:
    def run(self, agent_input: AgentInput) -> AgentExecution:
        started = perf_counter()
        docs = agent_input.retrieved_documents
        country = agent_input.plan.parsed_entities.get("country")
        region = agent_input.plan.parsed_entities.get("region")
        claims = supported_location_evidence(docs, country=country, region=region)
        aggregate = aggregate_geography(docs, group_by="region" if region else "country")
        result = AgentResult(
            agent_name="geographic", status=AgentStatus.SUCCESS if claims else AgentStatus.PARTIAL,
            input_summary={"country": country, "region": region},
            output_data={"supported_location_evidence": claims, "aggregation": aggregate,
                         "source_associated_countries_are_not_incident_locations": True},
            source_record_ids=list(dict.fromkeys(str(c.get("source_record_id", "")) for c in claims if c.get("source_record_id"))),
            missing_information=[] if claims else ["No supported incident, target, or victim location evidence was found in retrieved records."],
            warnings=["General mentions, claimed actor origins, and infrastructure locations are excluded from incident/target/victim counts."],
            execution_duration_ms=(perf_counter() - started) * 1000,
        )
        return AgentExecution(result=result)


class ThreatCorrelationAgent:
    def __init__(self, engine: ThreatAnalysisEngine):
        self.engine = engine

    def run(self, agent_input: AgentInput) -> AgentExecution:
        started = perf_counter()
        records = _canonical_records(agent_input.retrieved_documents)
        analyzed = self.engine.correlator.correlate(records)
        correlations = [item.model_dump(mode="json") for item in analyzed]
        ids = sorted({str(item.get("source_record_id")) for item in correlations} | {str(item.get("related_record_id")) for item in correlations}) if correlations else []
        result = AgentResult(agent_name="correlation", status=AgentStatus.SUCCESS if correlations else AgentStatus.PARTIAL,
            input_summary={"distinct_source_records": len(records)}, output_data={"correlations": correlations,
            "confidence_semantics": "uncalibrated evidence-strength heuristic; not probability"},
            source_record_ids=ids, missing_information=[] if correlations else ["No sufficiently supported record relationships were found."],
            execution_duration_ms=(perf_counter() - started) * 1000)
        return AgentExecution(result=result)


class ContextualRiskAgent:
    def __init__(self, engine: ThreatAnalysisEngine):
        self.engine = engine

    def run(self, agent_input: AgentInput) -> AgentExecution:
        started = perf_counter()
        records = _canonical_records(agent_input.retrieved_documents)
        values = [self.engine.priority_assessor.assess(record, agent_input.plan.priority_context).model_dump(mode="json") for record in records]
        result = AgentResult(agent_name="contextual_risk", status=AgentStatus.SUCCESS if values else AgentStatus.PARTIAL,
            input_summary={"distinct_source_records": len(records), "context": agent_input.plan.priority_context.model_dump(mode="json")},
            output_data={"contextual_priorities": values, "score_semantics": "explainable contextual review priority; not attack prediction"},
            source_record_ids=[v["source_record_id"] for v in values], missing_information=[] if values else ["No canonical source records were available for contextual prioritization."],
            execution_duration_ms=(perf_counter() - started) * 1000)
        return AgentExecution(result=result)
