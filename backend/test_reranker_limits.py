from langchain_core.documents import Document

from app.rag.reranker import CTIReranker


class WordTokenizer:
    def encode(self, text, add_special_tokens=False, truncation=False, max_length=None):
        tokens = text.split()
        return tokens[:max_length] if truncation and max_length else tokens

    def decode(self, token_ids, skip_special_tokens=True):
        return " ".join(token_ids)

    def num_special_tokens_to_add(self, pair=True):
        return 3


class FakeCrossEncoder:
    tokenizer = WordTokenizer()

    def predict(self, pairs):
        self.pairs = pairs
        return [-0.7, 2.4]


def test_short_and_long_documents_fit_token_budget_and_keep_key_metadata():
    reranker = CTIReranker.__new__(CTIReranker)
    reranker.max_length = 48
    reranker.model = FakeCrossEncoder()
    short = Document(
        page_content="Short evidence.",
        metadata={"title": "Short report", "attack_ids": ["T1486"]},
    )
    long = Document(
        page_content="evidence " * 1000,
        metadata={
            "title": "Long report",
            "malware_families": ["TestLocker"],
            "attack_ids": ["T1486"],
            "countries": ["India"],
            "geography_semantics": "source_association_only",
        },
    )

    results = reranker.rerank("query about T1486", [short, long], top_k=2)

    assert [document for document, _ in results] == [long, short]
    assert [score for _, score in results] == [2.4, -0.7]
    assert reranker.SCORE_TYPE == "cross_encoder_relevance_logit"
    for query, document_text in reranker.model.pairs:
        assert len(query.split()) + len(document_text.split()) + 3 <= reranker.max_length
    long_pair_text = reranker.model.pairs[1][1]
    assert "Long report" in long_pair_text
    assert "TestLocker" in long_pair_text
    assert "T1486" in long_pair_text
    assert "India" in long_pair_text
    assert "evidence" in long_pair_text


def test_reranker_handles_empty_and_top_k_validation():
    reranker = CTIReranker.__new__(CTIReranker)
    reranker.max_length = 64
    reranker.model = FakeCrossEncoder()

    assert reranker.rerank("query", [], top_k=3) == []
