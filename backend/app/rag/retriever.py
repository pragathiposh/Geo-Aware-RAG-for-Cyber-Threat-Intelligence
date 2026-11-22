from langchain_core.documents import Document

from app.embeddings.model import EmbeddingModel
from app.vector_db.faiss_store import FAISSVectorStore
from app.rag.metadata_filter import CTIMetadataFilter
from app.rag.document_identity import get_chunk_id


class RAGRetriever:
    """
    RAG-level retriever for the Cyber Threat Intelligence system.

    Responsibilities:
        1. Load the embedding model.
        2. Load the persistent FAISS vector store.
        3. Convert a user query into an embedding.
        4. Retrieve semantically relevant CTI documents.
        5. Apply optional metadata filters.
    """

    def __init__(
        self,
        vector_store_path: str = "data/vector_store_phase1",
    ) -> None:

        self.vector_store_path = vector_store_path

        print("Initializing RAG retriever...")

        print("Loading embedding model...")

        self.embedding_model = EmbeddingModel()

        print("Embedding model ready.")

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
        filters: dict[str, str] | None = None,
        candidate_k: int = 20,
    ) -> list[tuple[Document, float]]:
        if not query or not query.strip():
            raise ValueError("Query cannot be empty.")

        if top_k <= 0:
            raise ValueError("top_k must be greater than zero.")

        if candidate_k <= 0:
            raise ValueError("candidate_k must be greater than zero.")

        query_embedding = self.embedding_model.encode_single(query.strip())

        candidates = self.vector_store.search(
            query_embedding,
            top_k=candidate_k,
        )

        print(f"Semantic candidates retrieved: {len(candidates)}")

        # ------------------------------------------------------
        # Metadata filtering
        # ------------------------------------------------------

        if filters:
            documents = [
                document
                for document, score in candidates
            ]

            filtered_documents = CTIMetadataFilter.filter_documents(
                documents=documents,
                filters=filters,
            )

            filtered_ids = {
                id(document)
                for document in filtered_documents
            }

            candidates = [
                (document, score)
                for document, score in candidates
                if id(document) in filtered_ids
            ]

            print(
                f"Documents after metadata filtering: "
                f"{len(candidates)}"
            )

        # ------------------------------------------------------
        # Deduplicate exact chunks only. Multiple chunks from one source record
        # may each contain distinct evidence and remain eligible.
        # ------------------------------------------------------

        unique_candidates: list[tuple[Document, float]] = []
        seen_chunks: set[str] = set()

        for document, score in candidates:
            chunk_id = get_chunk_id(document)
            if chunk_id in seen_chunks:
                continue

            seen_chunks.add(chunk_id)

            unique_candidates.append(
                (document, score)
            )

            if len(unique_candidates) >= top_k:
                break

        print(
            f"Unique documents after deduplication: "
            f"{len(unique_candidates)}"
        )

        return unique_candidates


    def retrieve_semantic(
        self,
        query: str,
        top_k: int = 20,
    ) -> list[tuple[Document, float]]:
        """
        Perform raw semantic retrieval using FAISS.

        This method intentionally does not apply metadata filters
        or deduplication.

        It is used by the Hybrid Retriever so that semantic and
        lexical retrieval can independently generate candidates
        before fusion.
        """

        if not query or not query.strip():
            raise ValueError("Query cannot be empty.")

        if top_k <= 0:
            raise ValueError(
                "top_k must be greater than zero."
            )

        query_embedding = self.embedding_model.encode_single(
            query.strip()
        )

        results = self.vector_store.search(
            query_embedding,
            top_k=top_k,
        )

        return results
