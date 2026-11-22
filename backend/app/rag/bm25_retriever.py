import re
from langchain_core.documents import Document
from rank_bm25 import BM25Okapi


class CTIBM25Retriever:
    """
    BM25 lexical retriever for Cyber Threat Intelligence documents.

    BM25 provides keyword-based retrieval that complements
    semantic FAISS retrieval.

    The retriever:
        1. Tokenizes CTI documents
        2. Builds a BM25 index
        3. Tokenizes the user query
        4. Scores documents using BM25
        5. Returns the highest-scoring candidates
    """

    def __init__(self, documents: list[Document]):
        if not documents:
            raise ValueError("Documents cannot be empty.")

        self.documents = documents

        self.tokenized_documents = [
            self.tokenize(self.build_document_text(document))
            for document in documents
        ]

        self.bm25 = BM25Okapi(self.tokenized_documents)

    @staticmethod
    def tokenize(text: str) -> list[str]:
        if not text:
            return []

        text = text.lower()

        return re.findall(
            r"\b[a-zA-Z0-9][a-zA-Z0-9._-]*\b",
            text,
        )

    @staticmethod
    def build_document_text(document: Document) -> str:
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

    def retrieve(
        self,
        query: str,
        top_k: int = 20,
    ) -> list[tuple[Document, float]]:

        if not query or not query.strip():
            raise ValueError("Query cannot be empty.")

        if top_k <= 0:
            raise ValueError("top_k must be greater than zero.")

        query_tokens = self.tokenize(query)

        if not query_tokens:
            return []

        scores = self.bm25.get_scores(query_tokens)

        ranked_indices = sorted(
            range(len(scores)),
            key=lambda index: scores[index],
            reverse=True,
        )

        results: list[tuple[Document, float]] = []

        for index in ranked_indices[:top_k]:
            score = float(scores[index])

            if score <= 0:
                continue

            results.append(
                (
                    self.documents[index],
                    score,
                )
            )

        return results