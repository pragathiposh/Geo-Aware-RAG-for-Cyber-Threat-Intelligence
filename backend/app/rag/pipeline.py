"""Compatibility facade for the centrally orchestrated CTI RAG pipeline."""

from __future__ import annotations

from typing import Any

from app.agents.orchestrator import CTIAgentOrchestrator
from app.agents.planner import QueryUnderstandingAgent
from app.agents.specialists import ContextualRiskAgent, GeographicIntelligenceAgent, RetrievalAgent, ThreatCorrelationAgent
from app.rag.generator import CTIGenerator
from app.rag.hybrid_retriever import CTIHybridRetriever
from app.rag.prompt import CTIPromptBuilder
from app.threat_analysis.analysis_engine import ThreatAnalysisEngine


class CTIRAGPipeline:
    """Construct each expensive retrieval/generation service once and share it."""

    def __init__(self, vector_store_path: str = "data/vector_store_phase1",
                 model_name: str = "Qwen/Qwen2.5-1.5B-Instruct", top_k: int = 5,
                 max_new_tokens: int = 300, *, retriever: Any | None = None,
                 generator: Any | None = None, prompt_builder: Any | None = None,
                 specialist_timeout: float = 20.0) -> None:
        self.top_k = top_k
        # A single hybrid retrieval service is shared by all orchestration paths.
        self.retriever = retriever or CTIHybridRetriever(vector_store_path=vector_store_path, fusion_strategy="weighted")
        self.prompt_builder = prompt_builder or CTIPromptBuilder()
        self.generator = generator or CTIGenerator(model_name=model_name, max_new_tokens=max_new_tokens)
        self.analysis_engine = ThreatAnalysisEngine()
        self.orchestrator = CTIAgentOrchestrator(
            planner=QueryUnderstandingAgent(), retrieval_agent=RetrievalAgent(self.retriever),
            geo_agent=GeographicIntelligenceAgent(),
            correlation_agent=ThreatCorrelationAgent(self.analysis_engine),
            risk_agent=ContextualRiskAgent(self.analysis_engine),
            prompt_builder=self.prompt_builder, generator=self.generator,
            specialist_timeout=specialist_timeout,
        )

    def query(self, user_query: str, top_k: int | None = None,
              max_new_tokens: int | None = None) -> dict[str, Any]:
        if not user_query or not user_query.strip():
            raise ValueError("User query cannot be empty.")
        # Preserve direct component wiring used by existing integrations/tests
        # that construct the pipeline with __new__ and inject a legacy retriever.
        if not hasattr(self, "orchestrator"):
            docs = self.retriever.retrieve(query=user_query, top_k=top_k if top_k is not None else self.top_k)
            prompt = self.prompt_builder.build_prompt(query=user_query, documents=docs)
            answer = self.generator.generate(prompt=prompt, max_new_tokens=max_new_tokens)
            return {"query": user_query, "answer": answer, "retrieved_documents": docs, "prompt": prompt}
        return self.orchestrator.run(user_query, top_k=top_k if top_k is not None else self.top_k,
                                     max_new_tokens=max_new_tokens)
