from pathlib import Path
import json
import pickle

import faiss
import numpy as np
from langchain_core.documents import Document


class FAISSVectorStore:
    """
    FAISS-based vector store for the Geo-Aware RAG
    Cyber Threat Intelligence system.

    The vector store maintains:
        1. FAISS similarity index
        2. Corresponding LangChain Documents
        3. Vector-store configuration metadata

    Embeddings are normalized before indexing so that
    Inner Product similarity approximates cosine similarity.
    """

    def __init__(self, dimension: int = 384):
        """
        Initialize an empty FAISS vector store.

        Args:
            dimension: Dimension of the embedding vectors.
        """

        self.dimension = dimension

        # IndexFlatIP performs exact inner-product similarity search.
        # Since vectors are normalized, this corresponds to cosine similarity.
        self.index: faiss.Index = faiss.IndexFlatIP(dimension)

        # Documents are kept in the same order as vectors in the FAISS index.
        self.documents: list[Document] = []

    # ---------------------------------------------------------
    # ADD DOCUMENTS
    # ---------------------------------------------------------

    def add_documents(
        self,
        documents: list[Document],
        embeddings: list[list[float]],
    ) -> None:
        """
        Add documents and their corresponding embeddings
        to the FAISS index.

        Args:
            documents: List of LangChain Document objects.
            embeddings: Corresponding embedding vectors.

        Raises:
            ValueError: If document and embedding counts differ.
            ValueError: If embeddings have an invalid shape.
            ValueError: If embedding dimension is incorrect.
        """

        if len(documents) != len(embeddings):
            raise ValueError(
                "Number of documents must match "
                "number of embeddings."
            )

        if not documents:
            return

        vectors = np.asarray(
            embeddings,
            dtype="float32",
        )

        # Ensure embeddings are represented as a 2D matrix.
        if vectors.ndim != 2:
            raise ValueError(
                "Embeddings must be a 2D array."
            )

        # Validate embedding dimension.
        if vectors.shape[1] != self.dimension:
            raise ValueError(
                f"Expected embedding dimension "
                f"{self.dimension}, "
                f"but received {vectors.shape[1]}."
            )

        # Normalize vectors.
        # After normalization, inner product = cosine similarity.
        faiss.normalize_L2(vectors)

        # Add vectors to FAISS.
        self.index.add(vectors)

        # Keep documents aligned with FAISS vector positions.
        self.documents.extend(documents)

    # ---------------------------------------------------------
    # SEARCH
    # ---------------------------------------------------------

    def search(
        self,
        query_embedding: list[float],
        top_k: int = 5,
    ) -> list[tuple[Document, float]]:
        """
        Search the FAISS index using a query embedding.

        Args:
            query_embedding: Embedding vector of the user query.
            top_k: Number of results to return.

        Returns:
            List of tuples containing:
                (Document, similarity_score)
        """

        # No vectors available.
        if self.index.ntotal == 0:
            return []

        query_vector = np.asarray(
            [query_embedding],
            dtype="float32",
        )

        # Validate query dimension.
        if query_vector.shape[1] != self.dimension:
            raise ValueError(
                f"Expected query dimension "
                f"{self.dimension}, "
                f"but received {query_vector.shape[1]}."
            )

        # Normalize query vector for cosine similarity.
        faiss.normalize_L2(query_vector)

        # Avoid requesting more results than vectors available.
        actual_k = min(
            top_k,
            self.index.ntotal,
        )

        scores, indices = self.index.search(
            query_vector,
            actual_k,
        )

        results: list[tuple[Document, float]] = []

        for score, index in zip(
            scores[0],
            indices[0],
        ):
            if index == -1:
                continue

            document = self.documents[index]

            results.append(
                (
                    document,
                    float(score),
                )
            )

        return results

    # ---------------------------------------------------------
    # SAVE
    # ---------------------------------------------------------

    def save(
        self,
        directory: str,
    ) -> None:
        """
        Persist the FAISS index, documents, and
        vector-store metadata to disk.

        Files created:

            index.faiss
            documents.pkl
            store_metadata.json
        """

        path = Path(directory)

        path.mkdir(
            parents=True,
            exist_ok=True,
        )

        index_path = path / "index.faiss"
        documents_path = path / "documents.pkl"
        metadata_path = path / "store_metadata.json"

        # -----------------------------------------------------
        # Save FAISS index
        # -----------------------------------------------------

        faiss.write_index(
            self.index,
            str(index_path),
        )

        # -----------------------------------------------------
        # Save corresponding documents
        # -----------------------------------------------------

        with open(
            documents_path,
            "wb",
        ) as file:

            pickle.dump(
                self.documents,
                file,
            )

        # -----------------------------------------------------
        # Save metadata
        # -----------------------------------------------------

        metadata = {
            "embedding_dimension": self.dimension,
            "index_type": "IndexFlatIP",
            "similarity": "cosine",
            "document_count": len(self.documents),
        }

        with open(
            metadata_path,
            "w",
            encoding="utf-8",
        ) as file:

            json.dump(
                metadata,
                file,
                indent=4,
            )

    # ---------------------------------------------------------
    # LOAD
    # ---------------------------------------------------------

    @classmethod
    def load(
        cls,
        directory: str,
    ) -> "FAISSVectorStore":
        """
        Load a previously saved FAISS vector store.

        The method loads:

            1. store_metadata.json
            2. index.faiss
            3. documents.pkl

        Args:
            directory: Directory containing the vector store.

        Returns:
            Loaded FAISSVectorStore instance.
        """

        path = Path(directory)

        index_path = path / "index.faiss"
        documents_path = path / "documents.pkl"
        metadata_path = path / "store_metadata.json"

        # -----------------------------------------------------
        # Validate required files
        # -----------------------------------------------------

        if not metadata_path.exists():
            raise FileNotFoundError(
                f"Metadata file not found: {metadata_path}"
            )

        if not index_path.exists():
            raise FileNotFoundError(
                f"FAISS index not found: {index_path}"
            )

        if not documents_path.exists():
            raise FileNotFoundError(
                f"Document store not found: {documents_path}"
            )

        # -----------------------------------------------------
        # Load metadata
        # -----------------------------------------------------

        with open(
            metadata_path,
            "r",
            encoding="utf-8",
        ) as file:

            metadata = json.load(file)

        embedding_dimension = metadata.get(
            "embedding_dimension"
        )

        if embedding_dimension is None:
            raise ValueError(
                "Embedding dimension is missing "
                "from store metadata."
            )

        # -----------------------------------------------------
        # Create store
        # -----------------------------------------------------

        store = cls(
            dimension=embedding_dimension
        )

        # -----------------------------------------------------
        # Load FAISS index
        # -----------------------------------------------------

        store.index = faiss.read_index(
            str(index_path)
        )

        # -----------------------------------------------------
        # Load documents
        # -----------------------------------------------------

        with open(
            documents_path,
            "rb",
        ) as file:

            store.documents = pickle.load(
                file
            )

        # -----------------------------------------------------
        # Validate index/document consistency
        # -----------------------------------------------------

        if store.index.ntotal != len(
            store.documents
        ):
            raise ValueError(
                "FAISS index and document store "
                "are inconsistent. "
                f"Vectors: {store.index.ntotal}, "
                f"Documents: {len(store.documents)}"
            )

        return store