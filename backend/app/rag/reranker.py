"""Cross-encoder reranking with an explicit input token budget."""

from __future__ import annotations

from typing import Any

from langchain_core.documents import Document
from sentence_transformers import CrossEncoder


class CTIReranker:
    """Rerank retrieved CTI chunks using cross-encoder relevance logits.

    Scores express model relevance logits; they are not calibrated
    probabilities or confidence values. Document pairs are token-budgeted to
    the model's configured maximum length, retaining a metadata header and
    then the leading document evidence.
    """

    SCORE_TYPE = "cross_encoder_relevance_logit"

    def __init__(
        self,
        model_name: str = "cross-encoder/ms-marco-MiniLM-L-6-v2",
        max_length: int = 512,
    ) -> None:
        if not model_name or not model_name.strip():
            raise ValueError("Reranker model name cannot be empty.")
        if max_length < 16:
            raise ValueError("max_length must be at least 16 tokens.")
        self.model_name = model_name
        self.max_length = max_length
        self.model = CrossEncoder(model_name, max_length=max_length)

    @staticmethod
    def _metadata_header(document: Document) -> str:
        metadata = document.metadata
        fields = (
            ("Title", metadata.get("title")),
            ("Malware", metadata.get("malware_families")),
            ("ATT&CK", metadata.get("attack_ids")),
            ("Industry", metadata.get("industries")),
            ("Source country association", metadata.get("countries")),
            ("Tags", metadata.get("tags")),
        )
        return " ".join(
            f"{label}: {value}"
            for label, value in fields
            if value is not None and str(value).strip()
        )

    @classmethod
    def build_document_text(cls, document: Document) -> str:
        """Build readable full text; truncation happens token-wise later."""
        header = cls._metadata_header(document)
        body = document.page_content or ""
        return f"{header}\n{body}".strip()

    def _encode(self, tokenizer: Any, text: str) -> list[int]:
        if not text:
            return []
        return list(tokenizer.encode(
            text,
            add_special_tokens=False,
            truncation=True,
            max_length=self.max_length,
        ))

    @staticmethod
    def _decode(tokenizer: Any, token_ids: list[int]) -> str:
        return tokenizer.decode(token_ids, skip_special_tokens=True) if token_ids else ""

    def prepare_pair(self, query: str, document: Document) -> tuple[str, str]:
        """Truncate query and document by tokenizer length before prediction."""
        tokenizer = self.model.tokenizer
        special_tokens = getattr(tokenizer, "num_special_tokens_to_add", None)
        special_count = special_tokens(pair=True) if special_tokens else 3
        budget = max(2, self.max_length - special_count)

        query_ids = self._encode(tokenizer, query.strip())
        query_budget = min(len(query_ids), max(8, budget // 3))
        query_ids = query_ids[:query_budget]
        document_budget = max(1, budget - len(query_ids))

        header_ids = self._encode(tokenizer, self._metadata_header(document))
        body_ids = self._encode(tokenizer, document.page_content or "")
        if header_ids and body_ids and document_budget > 1:
            header_budget = min(len(header_ids), max(1, min(160, document_budget // 2)))
            header_budget = min(header_budget, document_budget - 1)
        else:
            header_budget = min(len(header_ids), document_budget)
        body_budget = max(0, document_budget - header_budget)

        selected_header = self._decode(tokenizer, header_ids[:header_budget])
        selected_body = self._decode(tokenizer, body_ids[:body_budget])
        document_text = f"{selected_header}\n{selected_body}".strip()
        return self._decode(tokenizer, query_ids), document_text

    def rerank(
        self,
        query: str,
        documents: list[Document],
        top_k: int = 5,
    ) -> list[tuple[Document, float]]:
        if not query or not query.strip():
            raise ValueError("Query cannot be empty.")
        if not documents:
            return []
        if top_k <= 0:
            raise ValueError("top_k must be greater than zero.")

        pairs = [self.prepare_pair(query, document) for document in documents]
        scores = self.model.predict(pairs)
        if len(scores) != len(documents):
            raise ValueError("Cross-encoder returned a score count that does not match candidate count.")
        scored = [(document, float(score)) for document, score in zip(documents, scores)]
        scored.sort(key=lambda item: item[1], reverse=True)
        return scored[:min(top_k, len(scored))]
