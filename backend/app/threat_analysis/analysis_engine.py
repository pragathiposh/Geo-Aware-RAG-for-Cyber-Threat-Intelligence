"""Central orchestration for independent correlation and priority analyses."""

from __future__ import annotations

from typing import Any, Iterable

from app.threat_analysis.correlation import (
    CorrelationConfig,
    ThreatCorrelationEngine,
)
from app.threat_analysis.priority import (
    ContextualPriorityAssessor,
    PriorityConfig,
    PriorityContext,
)


class ThreatAnalysisEngine:
    """Coordinate CTI analysis without combining correlation and priority."""

    def __init__(
        self,
        correlation_config: CorrelationConfig | None = None,
        priority_config: PriorityConfig | None = None,
    ):
        self.correlator = ThreatCorrelationEngine(correlation_config)
        self.priority_assessor = ContextualPriorityAssessor(priority_config)

    def analyze(
        self,
        records: Iterable[Any],
        context: PriorityContext | None = None,
    ) -> dict[str, list[dict[str, Any]]]:
        """Return flat pairwise correlations and per-record priority separately."""
        rows = list(records)
        correlations = [item.model_dump(mode="json") for item in self.correlator.correlate(rows)]
        priorities = [
            self.priority_assessor.assess(record, context).model_dump(mode="json")
            for record in rows
        ]
        return {"correlations": correlations, "contextual_priorities": priorities}
