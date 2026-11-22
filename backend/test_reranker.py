from app.rag.bm25_retriever import CTIBM25Retriever
from app.rag.reranker import CTIReranker
from app.vector_db.faiss_store import FAISSVectorStore


VECTOR_STORE_PATH = "data/vector_store"

QUERY = "What ransomware attacks affected North America?"


def main():
    print("=" * 80)
    print("CTI RERANKER TEST")
    print("=" * 80)

    # --------------------------------------------------
    # 1. Load documents
    # --------------------------------------------------

    print("\nLoading vector store...")

    vector_store = FAISSVectorStore.load(
        VECTOR_STORE_PATH
    )

    documents = vector_store.documents

    print(
        f"Documents loaded: {len(documents)}"
    )

    # --------------------------------------------------
    # 2. Generate BM25 candidates
    # --------------------------------------------------

    print("\nInitializing BM25 retriever...")

    bm25 = CTIBM25Retriever(
        documents=documents
    )

    print(
        "BM25 retriever initialized."
    )

    candidates = bm25.retrieve(
        query=QUERY,
        top_k=20,
    )

    print(
        f"BM25 candidates retrieved: "
        f"{len(candidates)}"
    )

    candidate_documents = [
        document
        for document, _ in candidates
    ]

    # --------------------------------------------------
    # 3. Initialize reranker
    # --------------------------------------------------

    print("\nInitializing reranker...")

    reranker = CTIReranker()

    # --------------------------------------------------
    # 4. Rerank candidates
    # --------------------------------------------------

    print("\n" + "-" * 80)
    print("QUERY")
    print("-" * 80)

    print(QUERY)

    print("\nReranking candidates...")

    results = reranker.rerank(
        query=QUERY,
        documents=candidate_documents,
        top_k=5,
    )

    # --------------------------------------------------
    # 5. Display results
    # --------------------------------------------------

    print("\n" + "-" * 80)
    print("TOP RERANKED RESULTS")
    print("-" * 80)

    for rank, (
        document,
        score,
    ) in enumerate(
        results,
        start=1,
    ):

        print(f"\nRESULT {rank}")

        print(
            f"Title: "
            f"{document.metadata.get('title', 'Unknown')}"
        )

        print(
            f"Reranker Score: "
            f"{score:.4f}"
        )

        print(
            f"Countries: "
            f"{document.metadata.get('countries', 'Unknown')}"
        )

        print(
            f"Industries: "
            f"{document.metadata.get('industries', 'Unknown')}"
        )

        print(
            f"Malware: "
            f"{document.metadata.get('malware_families', 'Unknown')}"
        )

        print(
            f"ATT&CK IDs: "
            f"{document.metadata.get('attack_ids', 'Unknown')}"
        )

    print("\n" + "=" * 80)
    print("CTI RERANKER TEST COMPLETED")
    print("=" * 80)


if __name__ == "__main__":
    main()