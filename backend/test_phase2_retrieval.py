import pytest
from langchain_core.documents import Document

from app.rag.document_identity import get_chunk_id, get_source_record_id
from app.rag.hybrid_retriever import CTIHybridRetriever
from app.rag.metadata_filter import CTIMetadataFilter
from app.rag.retriever import RAGRetriever
from app.rag.retrieval_evaluation import (
    mean_reciprocal_rank,
    ndcg_at_k,
    recall_at_k,
    ranked_source_ids,
)


def doc(chunk, pulse="pulse-a", **metadata):
    return Document(
        page_content=f"evidence in {chunk}",
        metadata={"pulse_id": pulse, "source_record_id": pulse, "chunk_id": chunk, **metadata},
    )


def test_chunk_identity_keeps_sibling_chunks_and_source_identity_separate():
    first = doc("pulse-a:chunk:0")
    second = doc("pulse-a:chunk:1")

    assert get_source_record_id(first) == get_source_record_id(second) == "pulse-a"
    assert get_chunk_id(first) != get_chunk_id(second)


def test_legacy_chunk_identity_uses_content_within_same_source():
    first = Document(page_content="first evidence", metadata={"pulse_id": "p"})
    second = Document(page_content="second evidence", metadata={"pulse_id": "p"})

    assert get_source_record_id(first) == get_source_record_id(second)
    assert get_chunk_id(first) != get_chunk_id(second)


def test_hybrid_fusion_deduplicates_same_chunk_but_keeps_sibling_chunks():
    first, second = doc("p:chunk:0"), doc("p:chunk:1")
    fused = CTIHybridRetriever.fuse_candidates(
        [(first, 0.9), (second, 0.8)],
        [(first, 5.0)],
        strategy="rrf",
    )

    assert {get_chunk_id(document) for document, _ in fused} == {
        "p:chunk:0", "p:chunk:1"
    }
    assert len(fused) == 2


def test_semantic_retrieval_deduplicates_by_chunk_not_pulse():
    first, second = doc("p:chunk:0"), doc("p:chunk:1")
    retriever = RAGRetriever.__new__(RAGRetriever)
    retriever.embedding_model = type("Embedder", (), {"encode_single": lambda self, _: [1.0]})()
    retriever.vector_store = type("Store", (), {
        "search": lambda self, *_args, **_kwargs: [(first, 0.9), (second, 0.8), (first, 0.7)]
    })()

    results = retriever.retrieve("query", top_k=5)

    assert [get_chunk_id(document) for document, _ in results] == ["p:chunk:0", "p:chunk:1"]


@pytest.mark.parametrize(
    "metadata_country,requested,expected",
    [
        (["India"], "British Indian Ocean Territory", False),
        (["British Indian Ocean Territory"], "India", False),
        (["India", "British Indian Ocean Territory"], "India", True),
        (["United States"], "United States of America", True),
        (["United States of America"], "US", True),
        (["India"], "Indiana", False),
    ],
)
def test_country_filter_uses_exact_normalized_country_values(
    metadata_country, requested, expected
):
    document = Document(page_content="report", metadata={"countries": metadata_country})
    assert CTIMetadataFilter.matches(document, {"countries": requested}) is expected


def test_country_or_and_multi_field_semantics_are_preserved():
    documents = [
        Document(page_content="one", metadata={"countries": ["India"], "industries": ["Healthcare"]}),
        Document(page_content="two", metadata={"countries": ["United States"], "industries": ["Finance"]}),
        Document(page_content="three", metadata={"countries": ["Canada"], "industries": ["Healthcare"]}),
    ]
    matched = CTIMetadataFilter.filter_documents(
        documents,
        {"countries": "India|Canada", "industries": "Healthcare"},
    )
    assert [document.page_content for document in matched] == ["one", "three"]


def test_non_country_metadata_keeps_existing_containment_matching():
    document = Document(page_content="report", metadata={"malware_families": ["Kyber ransomware"]})
    assert CTIMetadataFilter.matches(document, {"malware_families": "Kyber"})


def test_source_country_filter_does_not_assign_a_location_role():
    document = Document(
        page_content="report mentions a country",
        metadata={"countries": ["India"], "geography_semantics": "source_association_only"},
    )
    assert CTIMetadataFilter.matches(document, {"countries": "India"})
    assert document.metadata["geography_semantics"] == "source_association_only"


def test_rrf_and_weighted_fusion_are_configurable_and_validate_strategy():
    a, b = doc("a"), doc("b", "pulse-b")
    semantic = [(a, 0.9), (b, 0.8)]
    lexical = [(b, 10.0), (a, 1.0)]
    weighted = CTIHybridRetriever.fuse_candidates(semantic, lexical, strategy="weighted")
    rrf = CTIHybridRetriever.fuse_candidates(semantic, lexical, strategy="rrf")

    assert {get_chunk_id(d) for d, _ in weighted} == {"a", "b"}
    assert {get_chunk_id(d) for d, _ in rrf} == {"a", "b"}
    with pytest.raises(ValueError):
        CTIHybridRetriever.fuse_candidates(semantic, lexical, strategy="unknown")


def test_rerank_pool_is_bounded_by_fusion_ranking():
    retriever = CTIHybridRetriever.__new__(CTIHybridRetriever)
    candidates = [(doc(f"p:chunk:{index}"), 1.0 - index / 10) for index in range(6)]
    retriever.retrieve_candidates = lambda **_: candidates

    class Reranker:
        documents = None

        def rerank(self, query, documents, top_k):
            self.documents = documents
            return [(document, float(index)) for index, document in enumerate(documents[:top_k])]

    retriever.reranker = Reranker()
    retriever.retrieve("query", top_k=2, candidate_k=4)

    assert [get_chunk_id(document) for document in retriever.reranker.documents] == [
        f"p:chunk:{index}" for index in range(4)
    ]


def test_evaluation_metrics_use_first_ranked_source_record():
    relevant = {"pulse-b"}
    docs = [doc("pulse-a:chunk:0", "pulse-a"), doc("pulse-a:chunk:1", "pulse-a"), doc("pulse-b:chunk:0", "pulse-b")]
    ids = ranked_source_ids(docs)

    assert ids == ["pulse-a", "pulse-b"]
    assert recall_at_k(ids, relevant, 5) == 1.0
    assert mean_reciprocal_rank(ids, relevant) == 0.5
    assert ndcg_at_k(ids, relevant, 5) == pytest.approx(1 / 1.5849625007)
