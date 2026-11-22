"""Compare weighted fusion and RRF on the versioned Phase 1 reference index."""

from __future__ import annotations

import argparse
import json
import statistics
import time
from pathlib import Path

from app.rag.bm25_retriever import CTIBM25Retriever
from app.rag.hybrid_retriever import CTIHybridRetriever
from app.rag.retrieval_evaluation import (
    mean_reciprocal_rank,
    ndcg_at_k,
    ranked_source_ids,
    recall_at_k,
)
from app.rag.reranker import CTIReranker
from app.rag.retriever import RAGRetriever


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--index", default="data/vector_store_phase1")
    parser.add_argument("--dataset", default="data/evaluation/phase2_retrieval.json")
    parser.add_argument("--candidate-k", type=int, default=100)
    parser.add_argument("--latency-repeats", type=int, default=3)
    args = parser.parse_args()
    if args.candidate_k <= 0 or args.latency_repeats <= 0:
        parser.error("candidate-k and latency-repeats must be positive")

    dataset = json.loads(Path(args.dataset).read_text(encoding="utf-8"))
    semantic = RAGRetriever(vector_store_path=args.index)
    lexical = CTIBM25Retriever(semantic.vector_store.documents)
    documents_by_row = {
        document.metadata.get("source_row"): document
        for document in semantic.vector_store.documents
    }
    for query_item in dataset["queries"]:
        for verified in query_item.get("verified_records", []):
            document = documents_by_row.get(verified["source_row"])
            if (
                document is None
                or str(document.metadata.get("source_record_id"))
                not in set(query_item["relevant_source_record_ids"])
                or document.metadata.get("title") != verified["title"]
            ):
                raise ValueError(
                    f"Evaluation label does not match the reference index: {query_item['query_id']} / row {verified['source_row']}"
                )
    strategies = ("weighted", "rrf")
    metrics = {name: {"recall@5": [], "mrr": [], "ndcg@5": []} for name in strategies}
    candidate_latencies: list[float] = []
    fusion_latencies: dict[str, list[float]] = {name: [] for name in strategies}
    end_to_end_latencies: dict[str, list[float]] = {name: [] for name in strategies}
    reranked_metrics = {name: {"recall@5": [], "mrr": [], "ndcg@5": []} for name in strategies}
    query_reports = []

    for item in dataset["queries"]:
        sem_results = lex_results = None
        for repeat in range(args.latency_repeats):
            start = time.perf_counter()
            sem_results = semantic.retrieve_semantic(item["query"], top_k=args.candidate_k)
            lex_results = lexical.retrieve(item["query"], top_k=args.candidate_k)
            candidate_latencies.append((time.perf_counter() - start) * 1000)

            for strategy in strategies:
                start = time.perf_counter()
                ranked = CTIHybridRetriever.fuse_candidates(
                    sem_results,
                    lex_results,
                    strategy=strategy,
                )
                fusion_latencies[strategy].append((time.perf_counter() - start) * 1000)
                if repeat == 0:
                    source_ids = ranked_source_ids([doc for doc, _ in ranked])
                    relevant = set(item["relevant_source_record_ids"])
                    values = {
                        "recall@5": recall_at_k(source_ids, relevant, 5),
                        "mrr": mean_reciprocal_rank(source_ids, relevant),
                        "ndcg@5": ndcg_at_k(source_ids, relevant, 5),
                    }
                    for metric, value in values.items():
                        metrics[strategy][metric].append(value)
                    query_reports.append((item["query_id"], strategy, values, source_ids[:5]))

    # Measure the complete retrieval path, including bounded cross-encoder
    # reranking. Reuse the loaded embedding model and BM25 index.
    hybrid = CTIHybridRetriever.__new__(CTIHybridRetriever)
    hybrid.semantic_retriever = semantic
    hybrid.bm25_retriever = lexical
    hybrid.semantic_weight = 0.7
    hybrid.lexical_weight = 0.3
    hybrid.rrf_k = 60
    hybrid.fusion_strategy = "weighted"
    hybrid.reranker = CTIReranker()
    for item in dataset["queries"]:
        for strategy in strategies:
            start = time.perf_counter()
            results = hybrid.retrieve(
                item["query"],
                top_k=5,
                candidate_k=args.candidate_k,
                fusion_strategy=strategy,
                rerank_candidate_k=20,
            )
            end_to_end_latencies[strategy].append((time.perf_counter() - start) * 1000)
            source_ids = ranked_source_ids([doc for doc, _ in results])
            relevant = set(item["relevant_source_record_ids"])
            reranked_metrics[strategy]["recall@5"].append(recall_at_k(source_ids, relevant, 5))
            reranked_metrics[strategy]["mrr"].append(mean_reciprocal_rank(source_ids, relevant))
            reranked_metrics[strategy]["ndcg@5"].append(ndcg_at_k(source_ids, relevant, 5))

    print(f"Reference index: {args.index}")
    print(f"Labeled queries: {len(dataset['queries'])} (positive-only examples; unlisted records unjudged)")
    print(f"Candidate depth per retriever: {args.candidate_k}; latency repeats: {args.latency_repeats}")
    for strategy in strategies:
        print(f"\n{strategy.upper()}")
        for metric, values in metrics[strategy].items():
            print(f"mean {metric}: {statistics.mean(values):.4f}")
        total_latencies = [
            candidate + fusion
            for candidate, fusion in zip(candidate_latencies, fusion_latencies[strategy])
        ]
        print(f"median candidate-generation + fusion latency (ms): {statistics.median(total_latencies):.2f}")
        print(f"median fusion-only latency (ms): {statistics.median(fusion_latencies[strategy]):.3f}")
        print(f"reranked mean Recall@5: {statistics.mean(reranked_metrics[strategy]['recall@5']):.4f}")
        print(f"reranked mean MRR: {statistics.mean(reranked_metrics[strategy]['mrr']):.4f}")
        print(f"reranked mean nDCG@5: {statistics.mean(reranked_metrics[strategy]['ndcg@5']):.4f}")
        print(f"median end-to-end latency with reranking (ms): {statistics.median(end_to_end_latencies[strategy]):.2f}")
    print("\nPer-query metric and top-5 details:")
    for query_id, strategy, values, top_ids in query_reports:
        print(query_id, strategy, values, top_ids)


if __name__ == "__main__":
    main()
