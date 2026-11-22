"""Offline tests for Phase 6 API contracts and route behavior.

This sandbox's installed Starlette/httpx TestClient blocks on any HTTP request,
including requests to an empty FastAPI app. These tests exercise the actual
route functions and Pydantic contracts directly without opening local sockets.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import HTTPException
from langchain_core.documents import Document
from pydantic import ValidationError

from app import main
from app.api.schemas import QueryRequest, QueryResponse


class FakePipeline:
    def __init__(self, *, fail: bool = False):
        self.fail = fail
        self.queries: list[str] = []

    def query(self, user_query: str) -> dict[str, Any]:
        self.queries.append(user_query)
        if self.fail:
            raise RuntimeError("private path: C:/secret/model-cache and stack information")
        doc = Document(page_content="Victims in India were affected by malware X.", metadata={
            "title": "Verified report", "source_record_id": "pulse-77", "chunk_id": "pulse-77:chunk:1",
            "countries": ["India"], "attack_ids": ["T1486"], "malware_families": ["Malware X"],
            "industries": ["Healthcare"], "source": "OTX", "source_row": 77,
            "geographic_evidence": [{"country": "India", "role": "victim_location", "status": "supported", "evidence_text": "Victims in India"}],
        })
        return {
            "query": user_query, "answer": "Report-backed response [S1].", "retrieved_documents": [(doc, 3.7)],
            "plan": {"selected_agents": ["query_planning", "retrieval", "geographic", "evidence_response"]},
            "agent_results": {
                "geographic": {"output_data": {"supported_location_evidence": [{"country": "India", "role": "victim_location"}]}, "missing_information": []},
                "correlation": {"output_data": {"correlations": []}, "missing_information": ["No relationships found."]},
                "contextual_risk": {"output_data": {"contextual_priorities": [{"source_record_id": "pulse-77", "contextual_priority_score": 42}]}, "missing_information": []},
            },
            "execution_trace": {"partial_execution": True, "entries": [{"agent_name": "correlation", "status": "partial"}]},
            "warnings": ["correlation: no supported relationships"],
        }


@pytest.fixture(autouse=True)
def clean_pipeline_state():
    old_pipeline = main.pipeline
    old_state = getattr(main.app.state, "pipeline", None)
    old_failed = getattr(main.app.state, "pipeline_init_failed", None)
    main.pipeline = None
    main.app.state.pipeline = None
    if hasattr(main.app.state, "pipeline_factory"):
        del main.app.state.pipeline_factory
    main.app.state.pipeline_init_failed = False
    yield
    main.pipeline = old_pipeline
    main.app.state.pipeline = old_state
    main.app.state.pipeline_init_failed = old_failed
    if hasattr(main.app.state, "pipeline_factory"):
        del main.app.state.pipeline_factory


def test_request_model_rejects_blank_and_oversized_queries_without_echoing_input():
    with pytest.raises(ValidationError):
        QueryRequest(query="   ")
    secret = "private-query-" + ("x" * 4001)
    with pytest.raises(ValidationError) as error:
        QueryRequest(query=secret)
    assert secret not in str(error.value)


def test_health_and_readiness_are_separate():
    assert main.health_check().status == "healthy"
    with pytest.raises(HTTPException) as error:
        main.readiness_check()
    assert error.value.status_code == 503
    main.app.state.pipeline = FakePipeline()
    assert main.readiness_check().pipeline_initialized is True


def test_pipeline_is_initialized_once_and_initialization_failure_is_not_retried():
    constructed = []
    fake = FakePipeline()
    main.app.state.pipeline_factory = lambda: (constructed.append(True) or fake)
    main.query_cti(QueryRequest(query="first"))
    main.query_cti(QueryRequest(query="second"))
    assert len(constructed) == 1

    failures = []
    main.app.state.pipeline = None
    main.pipeline = None
    main.app.state.pipeline_init_failed = False
    def fail_factory():
        failures.append(True)
        raise OSError("private model path")
    main.app.state.pipeline_factory = fail_factory
    for _ in range(2):
        with pytest.raises(HTTPException) as error:
            main.query_cti(QueryRequest(query="cannot load"))
        assert error.value.status_code == 500
        assert "private model path" not in str(error.value.detail)
    assert len(failures) == 1


def test_query_preserves_legacy_fields_and_exposes_phase5_findings():
    fake = FakePipeline()
    main.app.state.pipeline = fake
    response = main.query_cti(QueryRequest(query="  Where did Malware X affect victims?  "))
    body = response.model_dump(mode="json")
    assert {"query", "answer", "sources"}.issubset(body)
    assert body["query"] == "Where did Malware X affect victims?"
    assert body["sources"][0]["source_record_id"] == "pulse-77"
    assert body["sources"][0]["chunk_id"] == "pulse-77:chunk:1"
    assert body["sources"][0]["similarity_score"] == 3.7
    assert body["sources"][0]["country_associations"] == ["India"]
    assert body["geographic_findings"]["supported_location_evidence"][0]["role"] == "victim_location"
    assert body["contextual_priorities"][0]["contextual_priority_score"] == 42
    assert body["execution_plan"]["selected_agents"]
    assert body["execution_trace"]["partial_execution"] is True
    assert body["partial"] is True
    assert "No relationships found." in body["missing_evidence"]
    assert fake.queries == ["Where did Malware X affect victims?"]
    QueryResponse.model_validate(body)


def test_query_exceptions_are_logged_but_sanitized_for_clients(caplog):
    main.app.state.pipeline = FakePipeline(fail=True)
    with pytest.raises(HTTPException) as error:
        main.query_cti(QueryRequest(query="test"))
    assert error.value.status_code == 500
    serialized = str(error.value.detail)
    assert "private path" not in serialized
    assert "secret/model-cache" not in serialized
    assert "RuntimeError" not in serialized
    assert error.value.detail["error"]["code"] == "query_failed"
    assert "private path" in caplog.text


def test_serialized_agent_errors_and_private_prompts_are_sanitized():
    class DiagnosticPipeline:
        def query(self, user_query):
            return {"query": user_query, "answer": "evidence summary from D:\\workspace\\private.bin", "retrieved_documents": [],
                    "prompt": "private system prompt",
                    "agent_results": {"retrieval": {"status": "failed", "error": "RuntimeError: C:\\Users\\name\\model.bin",
                        "output_data": {"prompt": "private prompt"}, "missing_information": []}},
                    "execution_trace": {"partial_execution": True, "entries": [{"error": "C:\\Users\\secret\\trace.txt",
                        "warnings": ["generator failed: model cache at C:\\Users\\secret"]}]},
                    "warnings": ["generator exception: internal stack"], "plan": {}}

    main.app.state.pipeline = DiagnosticPipeline()
    body = main.query_cti(QueryRequest(query="test")).model_dump(mode="json")
    serialized = str(body)
    assert "C:\\Users" not in serialized
    assert "D:\\workspace" not in serialized
    assert "[redacted path]" in serialized
    assert "private prompt" not in serialized
    assert "RuntimeError" not in serialized
    assert "This analysis step could not be completed." in serialized


def test_query_openapi_response_model_and_cors_are_configured():
    schema = main.app.openapi()
    response_schema = schema["paths"]["/query"]["post"]["responses"]["200"]["content"]["application/json"]["schema"]
    assert response_schema["$ref"].endswith("QueryResponse")
    cors = next(middleware for middleware in main.app.user_middleware if middleware.cls.__name__ == "CORSMiddleware")
    assert "http://localhost:5173" in cors.kwargs["allow_origins"]
