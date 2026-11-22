import re
from typing import Any

from langchain_core.documents import Document


class CTILexicalRetriever:
    """
    Lightweight lexical retriever for Cyber Threat Intelligence.

    The retriever calculates a simple keyword-overlap score between
    the query and CTI documents.

    This is the first lightweight implementation of lexical retrieval.
    It can later be replaced or upgraded with BM25 without changing
    the overall RAG architecture.
    """

    # ------------------------------------------------------
    # Tokenization
    # ------------------------------------------------------

    @staticmethod
    def tokenize(text: str) -> list[str]:
        """
        Convert text into normalized tokens.

        Example:

            "What ransomware attacks affected India?"

        becomes approximately:

            ["what", "ransomware", "attacks", "affected", "india"]
        """

        if not text:
            return []

        text = text.lower()

        tokens = re.findall(
            r"\b[a-zA-Z0-9][a-zA-Z0-9._-]*\b",
            text,
        )

        return tokens

    # ------------------------------------------------------
    # Query keywords
    # ------------------------------------------------------

    @classmethod
    def extract_query_terms(cls, query: str) -> list[str]:
        """
        Extract meaningful terms from the query.

        Very common English stop words are removed so that
        cybersecurity-specific terms receive more importance.
        """

        stop_words = {
            "a",
            "an",
            "and",
            "are",
            "affected",
            "about",
            "be",
            "by",
            "for",
            "from",
            "in",
            "is",
            "of",
            "on",
            "or",
            "tell",
            "the",
            "to",
            "what",
            "which",
            "were",
            "with",
        }

        tokens = cls.tokenize(query)

        return [
            token
            for token in tokens
            if token not in stop_words
        ]

    # ------------------------------------------------------
    # Document text
    # ------------------------------------------------------

    @staticmethod
    def build_document_text(document: Document) -> str:
        """
        Combine the document content and useful CTI metadata
        into one searchable text representation.
        """

        metadata = document.metadata

        metadata_fields = [
            metadata.get("title", ""),
            metadata.get("countries", ""),
            metadata.get("industries", ""),
            metadata.get("malware_families", ""),
            metadata.get("attack_ids", ""),
            metadata.get("tags", ""),
        ]

        metadata_text = " ".join(
            str(value)
            for value in metadata_fields
            if value
        )

        return f"{document.page_content} {metadata_text}"

    # ------------------------------------------------------
    # Lexical score
    # ------------------------------------------------------

    @classmethod
    def calculate_score(
        cls,
        query_terms: list[str],
        document: Document,
    ) -> float:
        """
        Calculate a simple keyword-overlap score.

        Score range:

            0.0 → no query terms matched
            1.0 → all query terms matched

        This is intentionally lightweight and interpretable.
        """

        if not query_terms:
            return 0.0

        document_text = cls.build_document_text(document)
        document_tokens = set(
            cls.tokenize(document_text)
        )

        matched_terms = sum(
            1
            for term in query_terms
            if term in document_tokens
        )

        return matched_terms / len(query_terms)

    # ------------------------------------------------------
    # Retrieve
    # ------------------------------------------------------

    @classmethod
    def retrieve(
        cls,
        query: str,
        documents: list[Document],
        top_k: int = 20,
    ) -> list[tuple[Document, float]]:
        """
        Perform lightweight lexical retrieval.

        Documents with zero lexical overlap are excluded.
        """

        if not query or not query.strip():
            raise ValueError("Query cannot be empty.")

        if top_k <= 0:
            raise ValueError("top_k must be greater than zero.")

        query_terms = cls.extract_query_terms(query)

        scored_documents: list[
            tuple[Document, float]
        ] = []

        for document in documents:

            score = cls.calculate_score(
                query_terms=query_terms,
                document=document,
            )

            if score > 0:
                scored_documents.append(
                    (document, score)
                )

        scored_documents.sort(
            key=lambda item: item[1],
            reverse=True,
        )

        return scored_documents[:top_k]