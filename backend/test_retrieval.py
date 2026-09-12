from app.embeddings.model import EmbeddingModel
from app.vector_db.faiss_store import FAISSVectorStore


VECTOR_STORE_PATH = "data/vector_store"


print("=" * 70)
print("CTI RETRIEVAL EVALUATION")
print("=" * 70)


# --------------------------------------------------
# 1. Load embedding model
# --------------------------------------------------

print("\n[1] Loading embedding model...")

embedding_model = EmbeddingModel()

print("Embedding model ready.")


# --------------------------------------------------
# 2. Load persistent FAISS store
# --------------------------------------------------

print("\n[2] Loading FAISS vector store...")

vector_store = FAISSVectorStore.load(
    VECTOR_STORE_PATH
)

print(
    f"Loaded {vector_store.index.ntotal} vectors."
)


# --------------------------------------------------
# 3. Test queries
# --------------------------------------------------

queries = [
    "What malware threats are associated with ransomware?",
    "What cyber threats are reported in Japan?",
    "Which attacks use PowerShell?",
    "What threats target financial organizations?",
    "Which attacks involve data exfiltration?",
    "What malware families are mentioned in the dataset?",
]


# --------------------------------------------------
# 4. Run retrieval
# --------------------------------------------------

for query_number, query in enumerate(
    queries,
    start=1,
):

    print("\n")
    print("=" * 70)
    print(f"QUERY {query_number}")
    print("=" * 70)

    print(f"\nQuestion: {query}")

    # Generate query embedding
    query_embedding = (
        embedding_model.encode_single(query)
    )

    # Search FAISS
    results = vector_store.search(
        query_embedding,
        top_k=5,
    )

    print(
        f"\nRetrieved {len(results)} results."
    )

    # Display results
    for rank, (document, score) in enumerate(
        results,
        start=1,
    ):

        print(
            f"\n--- Result {rank} ---"
        )

        print(
            f"Similarity Score: {score:.4f}"
        )

        print(
            "Title:",
            document.metadata.get(
                "title",
                "Unknown",
            ),
        )

        print(
            "Countries:",
            document.metadata.get(
                "countries",
                "Unknown",
            ),
        )

        print(
            "Malware:",
            document.metadata.get(
                "malware_families",
                "Unknown",
            ),
        )

        print(
            "Attack IDs:",
            document.metadata.get(
                "attack_ids",
                "Unknown",
            ),
        )

        print(
            "Industries:",
            document.metadata.get(
                "industries",
                "Unknown",
            ),
        )


print("\n")
print("=" * 70)
print("RETRIEVAL EVALUATION COMPLETED")
print("=" * 70)