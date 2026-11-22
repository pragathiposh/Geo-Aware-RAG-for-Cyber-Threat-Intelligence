"""Semantic + lexical candidate fusion and cross-encoder reranking."""

from __future__ import annotations

import math

from langchain_core.documents import Document

from app.rag.bm25_retriever import CTIBM25Retriever
from app.rag.document_identity import get_chunk_id, get_source_record_id
from app.rag.metadata_filter import CTIMetadataFilter
from app.rag.reranker import CTIReranker
from app.rag.retriever import RAGRetriever


class CTIHybridRetriever:
    """Fuse FAISS and BM25 chunk candidates, then rerank the leading pool.

    ``weighted`` preserves the original score-normalization strategy. ``rrf``
    combines ranked lists using weighted Reciprocal Rank Fusion. Candidate
    identity is always chunk-level; source-record identity remains available
    separately for citations, grouping, and evaluation.
    """

    FUSION_STRATEGIES = {"weighted", "rrf"}

    def __init__(
        self,
        vector_store_path: str = "data/vector_store_phase1",
        semantic_weight: float = 0.7,
        lexical_weight: float = 0.3,
        reranker_model_name: str = "cross-encoder/ms-marco-MiniLM-L-6-v2",
        fusion_strategy: str = "weighted",
        rrf_k: int = 60,
    ) -> None:
        if not math.isfinite(semantic_weight) or semantic_weight < 0:
            raise ValueError("Semantic weight must be finite and non-negative.")
        if not math.isfinite(lexical_weight) or lexical_weight < 0:
            raise ValueError("Lexical weight must be finite and non-negative.")
        total_weight = semantic_weight + lexical_weight
        if total_weight <= 0:
            raise ValueError("At least one retrieval weight must be greater than zero.")
        if fusion_strategy not in self.FUSION_STRATEGIES:
            raise ValueError(f"fusion_strategy must be one of {sorted(self.FUSION_STRATEGIES)}")
        if rrf_k <= 0:
            raise ValueError("rrf_k must be greater than zero.")

        self.semantic_weight = semantic_weight / total_weight
        self.lexical_weight = lexical_weight / total_weight
        self.fusion_strategy = fusion_strategy
        self.rrf_k = rrf_k

        self.semantic_retriever = RAGRetriever(vector_store_path=vector_store_path)
        self.documents = self.semantic_retriever.vector_store.documents
        self.bm25_retriever = CTIBM25Retriever(documents=self.documents)
        self.reranker = CTIReranker(model_name=reranker_model_name)

    @staticmethod
    def get_document_id(document: Document) -> str:
        """Compatibility alias for source-record identity."""
        return get_source_record_id(document).casefold()

    @staticmethod
    def get_chunk_id(document: Document) -> str:
        return get_chunk_id(document)

    @classmethod
    def normalize_scores(
        cls,
        results: list[tuple[Document, float]],
    ) -> dict[str, float]:
        """Min-max normalize scores per stable chunk ID."""
        if not results:
            return {}
        scores = [float(score) for _, score in results]
        low, high = min(scores), max(scores)
        normalized: dict[str, float] = {}
        for document, score in results:
            value = 1.0 if high == low else (float(score) - low) / (high - low)
            chunk_id = get_chunk_id(document)
            normalized[chunk_id] = max(normalized.get(chunk_id, float("-inf")), value)
        return normalized

    @classmethod
    def fuse_candidates(
        cls,
        semantic_results: list[tuple[Document, float]],
        lexical_results: list[tuple[Document, float]],
        *,
        strategy: str = "weighted",
        semantic_weight: float = 0.7,
        lexical_weight: float = 0.3,
        rrf_k: int = 60,
    ) -> list[tuple[Document, float]]:
        """Return a chunk-deduplicated, fused candidate ranking."""
        if strategy not in cls.FUSION_STRATEGIES:
            raise ValueError(f"Unknown fusion strategy: {strategy}")
        if rrf_k <= 0:
            raise ValueError("rrf_k must be greater than zero.")
        total = semantic_weight + lexical_weight
        if (not math.isfinite(total) or semantic_weight < 0
                or lexical_weight < 0 or total <= 0):
            raise ValueError("Fusion weights must be finite, non-negative, and non-zero in total.")
        semantic_weight /= total
        lexical_weight /= total

        # Keep the first instance for a chunk ID. Semantic results are loaded
        # first so duplicate BM25 objects cannot replace their provenance.
        documents: dict[str, Document] = {}
        for document, _ in [*semantic_results, *lexical_results]:
            documents.setdefault(get_chunk_id(document), document)

        fused: dict[str, float] = {}
        if strategy == "weighted":
            semantic_scores = cls.normalize_scores(semantic_results)
            lexical_scores = cls.normalize_scores(lexical_results)
            for chunk_id in documents:
                fused[chunk_id] = (
                    semantic_weight * semantic_scores.get(chunk_id, 0.0)
                    + lexical_weight * lexical_scores.get(chunk_id, 0.0)
                )
        else:
            for results, weight in (
                (semantic_results, semantic_weight),
                (lexical_results, lexical_weight),
            ):
                ranked_seen: set[str] = set()
                rank = 0
                for document, _ in results:
                    chunk_id = get_chunk_id(document)
                    if chunk_id in ranked_seen:
                        continue
                    ranked_seen.add(chunk_id)
                    rank += 1
                    fused[chunk_id] = fused.get(chunk_id, 0.0) + weight / (rrf_k + rank)

        ranked_ids = sorted(documents, key=lambda key: fused.get(key, 0.0), reverse=True)
        return [(documents[key], fused[key]) for key in ranked_ids]

    def retrieve_candidates(
        self,
        query: str,
        candidate_k: int = 20,
        filters: dict[str, str] | None = None,
        fusion_strategy: str | None = None,
    ) -> list[tuple[Document, float]]:
        """Retrieve and fuse candidates without cross-encoder reranking."""
        if not query or not query.strip():
            raise ValueError("Query cannot be empty.")
        if candidate_k <= 0:
            raise ValueError("candidate_k must be greater than zero.")
        strategy = fusion_strategy or self.fusion_strategy
        if strategy not in self.FUSION_STRATEGIES:
            raise ValueError(f"fusion_strategy must be one of {sorted(self.FUSION_STRATEGIES)}")

        semantic = self.semantic_retriever.retrieve_semantic(query.strip(), top_k=candidate_k)
        lexical = self.bm25_retriever.retrieve(query.strip(), top_k=candidate_k)
        candidates = self.fuse_candidates(
            semantic,
            lexical,
            strategy=strategy,
            semantic_weight=self.semantic_weight,
            lexical_weight=self.lexical_weight,
            rrf_k=self.rrf_k,
        )
        if filters:
            candidates = [
                item for item in candidates
                if CTIMetadataFilter.matches(item[0], filters)
            ]
        return candidates

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
        filters: dict[str, str] | None = None,
        candidate_k: int = 20,
        fusion_strategy: str | None = None,
        rerank_candidate_k: int | None = None,
    ) -> list[tuple[Document, float]]:
        """Retrieve candidates and return cross-encoder relevance scores.

        Fusion score controls which candidates enter the bounded reranker pool;
        returned scores are raw cross-encoder relevance logits, not probabilities.
        """
        if top_k <= 0:
            raise ValueError("top_k must be greater than zero.")
        rerank_k = candidate_k if rerank_candidate_k is None else rerank_candidate_k
        if rerank_k <= 0:
            raise ValueError("rerank_candidate_k must be greater than zero.")
        candidates = self.retrieve_candidates(
            query=query,
            candidate_k=candidate_k,
            filters=filters,
            fusion_strategy=fusion_strategy,
        )
        pool = [document for document, _ in candidates[:rerank_k]]
        return self.reranker.rerank(query=query, documents=pool, top_k=top_k)
