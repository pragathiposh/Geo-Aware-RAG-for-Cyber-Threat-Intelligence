"""Deterministic query understanding and conditional agent planning."""

from __future__ import annotations

import re

from app.rag.filter_builder import CTIFilterBuilder
from app.rag.query_parser import CTIQueryParser
from app.agents.models import (
    AgentExecution,
    AgentExecutionPlan,
    AgentResult,
    AgentStatus,
    PriorityContext,
    QueryIntents,
)


class QueryUnderstandingAgent:
    """Reuse the CTI parser and add explicit task intents for the orchestrator."""

    AGENT_ORDER = ["query_planning", "retrieval", "geographic", "correlation", "contextual_risk", "evidence_response"]
    GEO_TERMS = re.compile(r"\b(?:geograph(?:y|ic|ical)?|where|country|countries|region|regions|located|location|victim(?:s)? in|target(?:ed|ing)? in|incident(?:s)? in|affected in)\b", re.I)
    CORRELATION_TERMS = re.compile(r"\b(?:related|relationship|correlat(?:e|ed|ion)|linked|connection|common campaign|same actor|associated with|overlap(?:ping)?)\b", re.I)
    RISK_TERMS = re.compile(r"\b(?:risk|priorit(?:y|ize|ise|ization|isation)|urgent|assess(?:ment)? risk|contextual priority)\b", re.I)

    def __init__(self, parser: CTIQueryParser | None = None):
        self.parser = parser or CTIQueryParser()

    def run(self, query: str) -> AgentExecution:
        parsed = self.parser.parse(query)
        geographic = bool(parsed.get("country") or parsed.get("region") or self.GEO_TERMS.search(query))
        correlation = bool(self.CORRELATION_TERMS.search(query))
        contextual_risk = bool(self.RISK_TERMS.search(query))
        intents = QueryIntents(geographic=geographic, correlation=correlation, contextual_risk=contextual_risk)

        filters = CTIFilterBuilder.build_filters(parsed)
        # Countries in the corpus are source associations. For a geo-intent
        # query, retrieve broadly and apply supported geographic evidence later.
        if geographic:
            filters.pop("countries", None)

        selected = ["query_planning", "retrieval"]
        reasons = {
            "query_planning": "Every request is parsed and converted into a structured plan.",
            "retrieval": "Every answer is grounded in retrieved CTI evidence.",
        }
        if geographic:
            selected.append("geographic")
            reasons["geographic"] = "A country, region, location, or geographic question was detected; use supported location evidence."
        if correlation:
            selected.append("correlation")
            reasons["correlation"] = "The query asks about related entities, relationships, links, or shared activity."
        if contextual_risk:
            selected.append("contextual_risk")
            reasons["contextual_risk"] = "The query asks for risk, priority, urgency, or prioritization."
        selected.append("evidence_response")
        reasons["evidence_response"] = "Every request needs an evidence-grounded response or explicit insufficient-evidence result."

        plan = AgentExecutionPlan(
            query=query,
            parsed_entities=parsed,
            intents=intents,
            selected_agents=selected,
            selection_reasons=reasons,
            metadata_filters=filters,
            priority_context=PriorityContext(
                industry=parsed.get("industry"),
                country=parsed.get("country"),
                region=parsed.get("region"),
            ),
        )
        result = AgentResult(
            agent_name="query_planning", status=AgentStatus.SUCCESS,
            input_summary={"query": query},
            output_data={"plan": plan.model_dump(mode="json")},
        )
        return AgentExecution(result=result, artifacts={"plan": plan})
