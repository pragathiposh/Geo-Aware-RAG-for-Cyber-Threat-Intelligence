from typing import Any

from langchain_core.documents import Document

from app.embeddings.model import EmbeddingModel
from app.vector_db.faiss_store import FAISSVectorStore


class RAGRetriever:
    """
    RAG-level retriever for the Cyber Threat Intelligence system.

    Responsibilities:
        1. Load the embedding model.
        2. Load the persistent FAISS vector store.
        3. Convert a user query into an embedding.
        4. Retrieve the most relevant CTI documents.
    """

    def __init__(
        self,
        vector_store_path: str = "data/vector_store",
    ) -> None:

        self.vector_store_path = vector_store_path

        print("Initializing RAG retriever...")

        # Load embedding model
        print("Loading embedding model...")
        self.embedding_model = EmbeddingModel()
        print("Embedding model ready.")

        # Load persistent FAISS vector store
        print("Loading FAISS vector store...")
        self.vector_store = FAISSVectorStore.load(
            vector_store_path
        )
        print(
            f"FAISS vector store loaded: "
            f"{self.vector_store.index.ntotal} vectors."
        )

        print("RAG retriever initialized successfully.")

    def retrieve(
        self,
        query: str,
        top_k: int = 5,
    ) -> list[tuple[Document, float]]:
        """
        Retrieve the most relevant CTI documents for a query.

        Args:
            query: User's cybersecurity question.
            top_k: Number of documents to retrieve.

        Returns:
            List of tuples containing:
                - LangChain Document
                - Similarity score
        """

        if not query or not query.strip():
            raise ValueError(
                "Query cannot be empty."
            )

        if top_k <= 0:
            raise ValueError(
                "top_k must be greater than zero."
            )

        # Generate embedding for the user query
        query_embedding = (
            self.embedding_model.encode_single(
                query.strip()
            )
        )

        # Search FAISS
        results = self.vector_store.search(
            query_embedding,
            top_k=top_k,
        )

        return results

    def retrieve_with_metadata(
        self,
        query: str,
        top_k: int = 5,
    ) -> list[dict[str, Any]]:
        """
        Retrieve CTI documents and expose their
        metadata in a convenient dictionary format.

        This method will be useful later when we
        introduce geo-aware retrieval.
        """

        results = self.retrieve(
            query=query,
            top_k=top_k,
        )

        formatted_results = []

        for document, score in results:

            formatted_results.append(
                {
                    "content": document.page_content,
                    "score": score,
                    "metadata": document.metadata,
                }
            )

        return formatted_results