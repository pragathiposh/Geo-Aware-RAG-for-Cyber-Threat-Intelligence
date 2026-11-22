"""Model-free tests for Phase 5 orchestration contracts and failure paths."""

from langchain_core.documents import Document

from app.agents.models import AgentExecution, AgentExecutionPlan, AgentResult, AgentStatus
from app.agents.orchestrator import CTIAgentOrchestrator
from app.agents.planner import QueryUnderstandingAgent
from app.agents.specialists import RetrievalAgent
from app.rag.pipeline import CTIRAGPipeline


class FakeRetriever:
    def __init__(self, documents=None, fail=False):
        self.documents = documents or []
        self.fail = fail

    def retrieve(self, query, top_k, filters=None):
        if self.fail:
            raise RuntimeError("offline index")
        return self.documents[:top_k]


class FakePrompt:
    def build_prompt(self, query, documents):
        return f"Question: {query}; evidence: {len(documents)}"


class FakeGenerator:
    def __init__(self, answer="Supported [S1]."):
        self.answer = answer

    def generate(self, prompt, max_new_tokens=None):
        return self.answer


class NoopSpecialist:
    def run(self, agent_input):
        return AgentExecution(result=AgentResult(agent_name="unused", status=AgentStatus.SUCCESS))


def make_doc(source="pulse-1", chunk="chunk-1", text="Ransomware report", **metadata):
    return Document(page_content=text, metadata={"source_record_id": source, "chunk_id": chunk, "title": "Report", **metadata})


def make_orchestrator(retriever=None, generator=None, timeout=0.5):
    retriever = retriever or FakeRetriever([(make_doc(), 0.7)])
    from app.agents.specialists import GeographicIntelligenceAgent, ContextualRiskAgent, ThreatCorrelationAgent
    from app.threat_analysis.analysis_engine import ThreatAnalysisEngine
    engine = ThreatAnalysisEngine()
    return CTIAgentOrchestrator(QueryUnderstandingAgent(), RetrievalAgent(retriever), GeographicIntelligenceAgent(),
        ThreatCorrelationAgent(engine), ContextualRiskAgent(engine), FakePrompt(), generator or FakeGenerator(), specialist_timeout=timeout)


def test_planner_selects_specialists_conditionally_and_avoids_country_association_filter_for_geo():
    plan = QueryUnderstandingAgent().run("Where were ransomware victims in India? Compare related campaigns and prioritize healthcare risk.").artifacts["plan"]
    assert plan.intents.geographic and plan.intents.correlation and plan.intents.contextual_risk
    assert {"geographic", "correlation", "contextual_risk"}.issubset(plan.selected_agents)
    assert "countries" not in plan.metadata_filters


def test_general_query_does_not_run_specialists_and_keeps_legacy_result_keys():
    result = make_orchestrator().run("Summarize this ransomware report", top_k=3)
    assert {"query", "answer", "retrieved_documents", "prompt"}.issubset(result)
    assert all(result["execution_trace"]["entries"][i]["status"] == "skipped" for i in (2, 3, 4))
    assert result["execution_trace"]["entries"][-1]["status"] == "success"


def test_sibling_chunks_keep_distinct_chunk_identity_but_shared_source_provenance():
    docs = [(make_doc("same-pulse", "c1", "first evidence"), 0.9), (make_doc("same-pulse", "c2", "second evidence"), 0.8)]
    result = make_orchestrator(FakeRetriever(docs)).run("Summarize report", top_k=5)
    refs = result["agent_results"]["retrieval"]["evidence_references"]
    assert [ref["chunk_id"] for ref in refs] == ["c1", "c2"]
    assert [ref["source_record_id"] for ref in refs] == ["same-pulse", "same-pulse"]


def test_geo_request_reports_no_evidence_and_distinguishes_association():
    result = make_orchestrator(FakeRetriever([(make_doc(countries=["India"]), 0.7)])).run("Where did attacks occur in India?", top_k=5)
    geo = result["agent_results"]["geographic"]
    assert geo["status"] == "partial"
    assert geo["output_data"]["source_associated_countries_are_not_incident_locations"] is True
    assert geo["output_data"]["aggregation"]["source_association_counts"] == {"India": 1}
    assert not geo["output_data"]["supported_location_evidence"]


def test_retrieval_failure_is_traced_and_generation_skips_without_evidence():
    result = make_orchestrator(FakeRetriever(fail=True)).run("Show related campaigns", top_k=5)
    statuses = {entry["agent_name"]: entry["status"] for entry in result["execution_trace"]["entries"]}
    assert statuses["retrieval"] == "failed"
    assert statuses["correlation"] == "skipped"
    assert "insufficient" in result["answer"].lower()
    assert result["execution_trace"]["partial_execution"] is True


def test_uncited_generation_uses_source_linked_fallback():
    result = make_orchestrator(generator=FakeGenerator("An uncited answer.")).run("Summarize report", top_k=5)
    assert "[S1]" in result["answer"]
    assert result["agent_results"]["evidence_response"]["status"] == "partial"


def test_generator_timeout_returns_evidence_summary_and_trace_warning():
    import time

    class SlowGenerator:
        def generate(self, prompt, max_new_tokens=None):
            time.sleep(0.08)
            return "late answer [S1]"

    orchestrator = make_orchestrator(generator=SlowGenerator())
    orchestrator.generation_timeout = 0.01
    result = orchestrator.run("Summarize report", top_k=5)
    assert "timed out" in result["answer"].lower()
    assert result["agent_results"]["evidence_response"]["status"] == "partial"


def test_invalid_execution_plan_is_rejected():
    orchestrator = make_orchestrator()
    invalid = AgentExecutionPlan(query="x", selected_agents=["retrieval", "made_up"])
    try:
        orchestrator.validate_plan(invalid)
    except ValueError as exc:
        assert "unknown" in str(exc)
    else:
        raise AssertionError("invalid agent selection should be rejected")


def test_specialist_exception_and_timeout_are_reported_without_aborting_response():
    import time

    orchestrator = make_orchestrator(timeout=0.02)

    class Broken:
        def run(self, agent_input):
            raise RuntimeError("analysis unavailable")

    class Slow:
        def run(self, agent_input):
            time.sleep(0.08)
            return AgentExecution(result=AgentResult(agent_name="geographic", status=AgentStatus.SUCCESS))

    # Risk analysis fails and geo analysis times out; response still uses retrieval.
    orchestrator.risk_agent = Broken()
    orchestrator.geo_agent = Slow()
    result = orchestrator.run("Where are related ransomware risk priorities?", top_k=5)
    statuses = {entry["agent_name"]: entry["status"] for entry in result["execution_trace"]["entries"]}
    assert statuses["contextual_risk"] == "failed"
    assert statuses["geographic"] == "failed"
    assert result["answer"]
    assert result["execution_trace"]["partial_execution"] is True


def test_legacy_pipeline_manual_component_wiring_remains_supported():
    pipeline = CTIRAGPipeline.__new__(CTIRAGPipeline)
    pipeline.top_k = 1
    pipeline.retriever = FakeRetriever([(make_doc(), 0.8)])
    pipeline.prompt_builder = FakePrompt()
    pipeline.generator = FakeGenerator()
    result = pipeline.query("Question")
    assert result["answer"] == "Supported [S1]."
    assert result["retrieved_documents"]
