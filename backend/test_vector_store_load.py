from app.embeddings.model import EmbeddingModel
from app.vector_db.faiss_store import FAISSVectorStore


VECTOR_STORE_PATH = "data/vector_store"


print("=" * 60)
print("FAISS PERSISTENCE TEST")
print("=" * 60)


# --------------------------------------------------
# 1. Load embedding model
# --------------------------------------------------

print("\n[1] Loading embedding model...")

embedding_model = EmbeddingModel()

print("Embedding model loaded.")


# --------------------------------------------------
# 2. Load existing FAISS vector store
# --------------------------------------------------

print("\n[2] Loading FAISS vector store...")

vector_store = FAISSVectorStore.load(
    VECTOR_STORE_PATH
)

print("FAISS vector store loaded successfully.")


# --------------------------------------------------
# 3. Display vector-store information
# --------------------------------------------------

print("\n[3] Vector store information")

print(
    "Embedding dimension:",
    vector_store.dimension
)

print(
    "Number of vectors:",
    vector_store.index.ntotal
)

print(
    "Number of documents:",
    len(vector_store.documents)
)


# --------------------------------------------------
# 4. Create test query
# --------------------------------------------------

query = (
    "What malware threats are associated "
    "with cyber attacks?"
)

print("\n[4] Query:")
print(query)


# --------------------------------------------------
# 5. Generate query embedding
# --------------------------------------------------

print("\n[5] Generating query embedding...")

query_embedding = (
    embedding_model.encode_single(query)
)


# --------------------------------------------------
# 6. Search
# --------------------------------------------------

print("\n[6] Performing similarity search...")

results = vector_store.search(
    query_embedding,
    top_k=5,
)


# --------------------------------------------------
# 7. Display results
# --------------------------------------------------

print("\n" + "=" * 60)
print("SEARCH RESULTS")
print("=" * 60)


for rank, (document, score) in enumerate(
    results,
    start=1,
):

    print(
        f"\n--- Result {rank} ---"
    )

    print(
        f"Similarity score: {score:.4f}"
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


# --------------------------------------------------
# 8. Final validation
# --------------------------------------------------

print("\n" + "=" * 60)

if vector_store.index.ntotal == len(
    vector_store.documents
):
    print(
        "PERSISTENCE TEST: SUCCESS"
    )
else:
    print(
        "PERSISTENCE TEST: FAILED"
    )

print("=" * 60)