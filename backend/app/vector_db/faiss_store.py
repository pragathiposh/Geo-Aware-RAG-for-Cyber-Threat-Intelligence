from pathlib import Path
import pickle

import faiss
import numpy as np
from langchain_core.documents import Document


class FAISSVectorStore:
    """
    Simple FAISS vector store for the CTI RAG system.

    Stores:
        - FAISS similarity index
        - Corresponding LangChain Documents
    """

    def __init__(self, dimension: int = 384):
        self.dimension = dimension

        # Inner Product is used with normalized embeddings
        # to approximate cosine similarity.
        self.index: faiss.Index = faiss.IndexFlatIP(dimension)

        self.documents: list[Document] = []

    def add_documents(
        self,
        documents: list[Document],
        embeddings: list[list[float]],
    ) -> None:
        """
        Add documents and their embeddings to the FAISS index.
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

        if vectors.ndim != 2:
            raise ValueError(
                "Embeddings must be a 2D array."
            )

        if vectors.shape[1] != self.dimension:
            raise ValueError(
                f"Expected embedding dimension "
                f"{self.dimension}, "
                f"but received {vectors.shape[1]}."
            )

        # Normalize vectors so Inner Product
        # behaves like cosine similarity.
        faiss.normalize_L2(vectors)

        self.index.add(vectors)

        self.documents.extend(documents)

    def search(
        self,
        query_embedding: list[float],
        top_k: int = 5,
    ) -> list[tuple[Document, float]]:
        """
        Search the FAISS index and return the
        most relevant documents with similarity scores.
        """

        if self.index.ntotal == 0:
            return []

        query_vector = np.asarray(
            [query_embedding],
            dtype="float32",
        )

        if query_vector.shape[1] != self.dimension:
            raise ValueError(
                f"Expected query dimension "
                f"{self.dimension}, "
                f"but received {query_vector.shape[1]}."
            )

        faiss.normalize_L2(query_vector)

        actual_k = min(
            top_k,
            self.index.ntotal,
        )

        scores, indices = self.index.search(
            query_vector,
            actual_k,
        )

        results = []

        for score, index in zip(
            scores[0],
            indices[0],
        ):
            if index == -1:
                continue

            results.append(
                (
                    self.documents[index],
                    float(score),
                )
            )

        return results

    def save(self, directory: str) -> None:
        """
        Persist the FAISS index and documents.
        """

        path = Path(directory)
        path.mkdir(
            parents=True,
            exist_ok=True,
        )

        index_path = path / "index.faiss"
        documents_path = path / "documents.pkl"

        faiss.write_index(
            self.index,
            str(index_path),
        )

        with open(
            documents_path,
            "wb",
        ) as file:
            pickle.dump(
                self.documents,
                file,
            )

    @classmethod
    def load(
        cls,
        directory: str,
        dimension: int = 384,
    ) -> "FAISSVectorStore":
        """
        Load a previously saved FAISS vector store.
        """

        path = Path(directory)

        index_path = path / "index.faiss"
        documents_path = path / "documents.pkl"

        if not index_path.exists():
            raise FileNotFoundError(
                f"FAISS index not found: {index_path}"
            )

        if not documents_path.exists():
            raise FileNotFoundError(
                f"Document store not found: "
                f"{documents_path}"
            )

        store = cls(dimension=dimension)

        store.index = faiss.read_index(
            str(index_path)
        )

        with open(
            documents_path,
            "rb",
        ) as file:
            store.documents = pickle.load(file)

        return store