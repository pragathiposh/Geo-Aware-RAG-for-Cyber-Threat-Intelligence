"""FastAPI application for the GeoRAG-CTI local analysis pipeline."""

from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
import uuid
from typing import Any

# Keep local CPU inference's default BLAS/OpenMP pools modest. Existing user
# settings take precedence; this prevents a machine-wide logical-core count
# from multiplying per-worker memory in this local development app.
os.environ.setdefault("OPENBLAS_NUM_THREADS", "1")
os.environ.setdefault("OMP_NUM_THREADS", "1")

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder

from app.api.schemas import HealthResponse, QueryRequest, QueryResponse, ReadinessResponse, SourceDocument
from app.rag.document_identity import get_chunk_id, get_source_record_id

logger = logging.getLogger("georag.api")

SERVICE_NAME = "Geo-Aware RAG Cyber Threat Intelligence"
app = FastAPI(
    title=SERVICE_NAME,
    description="Evidence-grounded cyber threat intelligence retrieval and analysis.",
    version="0.6.0",
    debug=False,
)

cors_value = os.getenv("GEORAG_CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
allowed_origins = [origin.strip() for origin in cors_value.split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type", "X-Request-ID"],
)

# Kept as a module-level injection point for existing local integrations.
# Expensive embedding/reranker/generator construction happens on first query,
# not at import or health-check time.
pipeline: Any | None = None
_pipeline_lock = threading.Lock()


def _new_pipeline():
    # Keep API health/readiness/import paths free of Torch/transformer loads.
    from app.rag.pipeline import CTIRAGPipeline

    return CTIRAGPipeline(
        vector_store_path=os.getenv("GEORAG_VECTOR_STORE_PATH", "data/vector_store_phase1"),
        model_name=os.getenv("GEORAG_GENERATOR_MODEL", "Qwen/Qwen2.5-1.5B-Instruct"),
        top_k=int(os.getenv("GEORAG_TOP_K", "5")),
        max_new_tokens=int(os.getenv("GEORAG_MAX_NEW_TOKENS", "250")),
        specialist_timeout=float(os.getenv("GEORAG_AGENT_TIMEOUT_SECONDS", "20")),
    )


def _get_pipeline() -> Any:
    global pipeline
    existing = getattr(app.state, "pipeline", None)
    if existing is not None:
        return existing
    with _pipeline_lock:
        existing = getattr(app.state, "pipeline", None) or pipeline
        if existing is None:
            if getattr(app.state, "pipeline_init_failed", False):
                raise RuntimeError("Pipeline initialization is unavailable until the service is restarted.")
            try:
                existing = app.state.pipeline_factory() if hasattr(app.state, "pipeline_factory") else _new_pipeline()
            except Exception as exc:
                app.state.pipeline_error_type = type(exc).__name__
                app.state.pipeline_init_failed = True
                logger.exception("Pipeline initialization failed")
                raise
            app.state.pipeline = existing
            app.state.pipeline_init_failed = False
            pipeline = existing
        return existing


class RequestLoggingMiddleware:
    """Pure ASGI request logger; avoids buffering request/response bodies."""

    def __init__(self, app):
        self.application = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.application(scope, receive, send)
            return
        request_id = uuid.uuid4().hex
        started = time.perf_counter()
        status_code = 500

        async def send_with_request_id(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                headers = list(message.get("headers", []))
                headers.append((b"x-request-id", request_id.encode("ascii")))
                message["headers"] = headers
            await send(message)

        try:
            await self.application(scope, receive, send_with_request_id)
        finally:
            logger.info("request_id=%s method=%s path=%s status=%d duration_ms=%.1f",
                        request_id, scope.get("method"), scope.get("path"), status_code,
                        (time.perf_counter() - started) * 1000)


app.add_middleware(RequestLoggingMiddleware)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, exc: RequestValidationError):
    # Do not echo the submitted query or Pydantic's raw input/context.
    fields = sorted({".".join(str(part) for part in error.get("loc", ())[1:]) or "request"
                     for error in exc.errors()})
    return JSONResponse(status_code=422, content={"error": {
        "code": "invalid_request", "message": "The request did not match the expected format.", "fields": fields,
    }})


@app.get("/health", response_model=HealthResponse)
def health_check() -> HealthResponse:
    """Liveness: confirms that the HTTP process is serving requests."""
    return HealthResponse(status="healthy", service=SERVICE_NAME)


@app.get("/ready", response_model=ReadinessResponse)
def readiness_check() -> ReadinessResponse:
    """Readiness: reports whether the local analysis pipeline is initialized."""
    ready = getattr(app.state, "pipeline", None) is not None or pipeline is not None
    if not ready:
        raise HTTPException(status_code=503, detail={
            "error": {"code": "pipeline_not_initialized", "message": "The analysis pipeline is not initialized yet."}
        })
    return ReadinessResponse(status="ready", pipeline_initialized=True)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, str):
        return [part.strip() for part in value.replace("|", ",").split(",") if part.strip()]
    return [value]


def _canonical(metadata: dict[str, Any]) -> dict[str, Any]:
    value = metadata.get("canonical_cti")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (ValueError, TypeError):
            return {}
    return value if isinstance(value, dict) else {}


def _sanitize_public(value: Any, *, key: str = "") -> Any:
    """Remove internal diagnostics and accidental local paths from responses."""
    if key in {"prompt", "stack_trace", "traceback"}:
        return None
    if key == "error" and value:
        return "This analysis step could not be completed."
    if isinstance(value, dict):
        return {str(name): clean for name, item in value.items()
                if (clean := _sanitize_public(item, key=str(name))) is not None}
    if isinstance(value, list):
        return [_sanitize_public(item, key=key) for item in value]
    if isinstance(value, str):
        if key == "warnings" and re.search(r"failed|exception|traceback|timed? ?out|internal|model load", value, re.I):
            return "An analysis step was unavailable; see its execution status."
        return re.sub(r"(?i)(?:[a-z]:\\[^\s,;\"']+|\\\\[^\\\s]+\\[^\s,;\"']+|/(?:home|users|tmp|var|opt)/[^\s,;\"']+)", "[redacted path]", value)
    return jsonable_encoder(value)


def _serialize_sources(result: dict[str, Any]) -> list[SourceDocument]:
    sources: list[SourceDocument] = []
    for rank, item in enumerate(result.get("retrieved_documents", []) or [], start=1):
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            continue
        document, score = item
        metadata = getattr(document, "metadata", {}) or {}
        canonical = _canonical(metadata)
        geo = canonical.get("geographic_evidence", metadata.get("geographic_evidence", [])) or []
        techniques = canonical.get("attack_techniques", metadata.get("attack_enrichment", [])) or []
        provenance = {key: metadata[key] for key in ("source", "source_row", "source_record_id", "pulse_id") if key in metadata}
        relevance_semantics = "cross-encoder relevance logit; not probability or factual confidence"
        sources.append(SourceDocument(
            rank=rank,
            title=_sanitize_public(str(metadata.get("title") or "Untitled CTI report")),
            source_record_id=_sanitize_public(get_source_record_id(document)),
            chunk_id=_sanitize_public(get_chunk_id(document)),
            similarity_score=float(score),
            retrieval_score_semantics=relevance_semantics,
            countries=jsonable_encoder(metadata.get("countries")),
            country_associations=jsonable_encoder(metadata.get("countries")),
            malware_families=jsonable_encoder(metadata.get("malware_families")),
            industries=jsonable_encoder(metadata.get("industries")),
            attack_ids=jsonable_encoder(metadata.get("attack_ids") or canonical.get("attack_techniques", [])),
            attack_techniques=jsonable_encoder(_as_list(techniques)),
            excerpt=_sanitize_public((getattr(document, "page_content", "") or "")[:1600]),
            provenance=_sanitize_public(jsonable_encoder(provenance)),
            geographic_evidence=jsonable_encoder(_as_list(geo)),
        ))
    return sources


@app.post("/query", response_model=QueryResponse)
def query_cti(request: QueryRequest) -> QueryResponse:
    request_id = uuid.uuid4().hex
    try:
        result = _get_pipeline().query(user_query=request.query)
        agent_results = result.get("agent_results", {}) or {}
        geo_data = (agent_results.get("geographic", {}).get("output_data", {}) or {})
        correlation_data = (agent_results.get("correlation", {}).get("output_data", {}) or {})
        priority_data = (agent_results.get("contextual_risk", {}).get("output_data", {}) or {})
        missing = [message for agent in agent_results.values() for message in (agent.get("missing_information") or [])]
        trace = result.get("execution_trace", {}) or {}
        return QueryResponse(
            query=request.query,
            answer=_sanitize_public(str(result.get("answer", ""))),
            sources=_serialize_sources(result),
            geographic_findings=_sanitize_public(jsonable_encoder(geo_data)),
            threat_correlations=_sanitize_public(jsonable_encoder(correlation_data.get("correlations", []))),
            contextual_priorities=_sanitize_public(jsonable_encoder(priority_data.get("contextual_priorities", []))),
            execution_plan=_sanitize_public(jsonable_encoder(result.get("plan", {}))),
            agent_results=_sanitize_public(jsonable_encoder(agent_results)),
            execution_trace=_sanitize_public(jsonable_encoder(trace)),
            warnings=_sanitize_public(jsonable_encoder(result.get("warnings", []))),
            missing_evidence=list(dict.fromkeys(missing)),
            partial=bool(trace.get("partial_execution", False)),
        )
    except Exception as exc:
        logger.exception("Query failed request_id=%s error_type=%s", request_id, type(exc).__name__)
        raise HTTPException(status_code=500, detail={
            "error": {"code": "query_failed", "message": "The CTI query could not be completed.", "request_id": request_id}
        }) from None
