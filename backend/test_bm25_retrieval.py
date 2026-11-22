from app.rag.bm25_retriever import CTIBM25Retriever
from app.vector_db.faiss_store import FAISSVectorStore


VECTOR_STORE_PATH = "data/vector_store"


def main():
    print("=" * 80)
    print("BM25 RETRIEVAL TEST")
    print("=" * 80)

    print("\nLoading vector store...")

    vector_store = FAISSVectorStore.load(
        VECTOR_STORE_PATH
    )

    documents = vector_store.documents

    print(f"Documents loaded: {len(documents)}")

    print("\nInitializing BM25 retriever...")

    retriever = CTIBM25Retriever(
        documents=documents
    )

    print("BM25 retriever initialized successfully.")

    query = (
        "What ransomware attacks affected "
        "healthcare organizations in India?"
    )

    print("\n" + "-" * 80)
    print("QUERY")
    print("-" * 80)
    print(query)

    results = retriever.retrieve(
        query=query,
        top_k=5,
    )

    print("\n" + "-" * 80)
    print("TOP BM25 RESULTS")
    print("-" * 80)

    for rank, (document, score) in enumerate(
        results,
        start=1,
    ):
        print(f"\nRESULT {rank}")
        print(f"Title: {document.metadata.get('title', 'Unknown')}")
        print(f"BM25 Score: {score:.4f}")
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
    print("BM25 RETRIEVAL TEST COMPLETED")
    print("=" * 80)


if __name__ == "__main__":
    main()