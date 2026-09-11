from app.rag.loader import load_cti_csv
from app.preprocessing.cleaner import clean_documents
from app.preprocessing.splitter import split_documents
from app.embeddings.model import EmbeddingModel
from app.vector_db.faiss_store import FAISSVectorStore


CSV_PATH = "data/raw/csv/1_otx_threat_intel.csv"

VECTOR_STORE_PATH = "data/vector_store"


print("======================================")
print("CTI VECTOR STORE TEST")
print("======================================")


# --------------------------------------------------
# 1. Load CTI documents
# --------------------------------------------------

print("\n[1] Loading CTI documents...")

documents = load_cti_csv(CSV_PATH)

print(
    f"Documents loaded: {len(documents)}"
)


# --------------------------------------------------
# 2. Clean documents
# --------------------------------------------------

print("\n[2] Cleaning documents...")

cleaned_documents = clean_documents(
    documents
)

print(
    f"Documents after cleaning: "
    f"{len(cleaned_documents)}"
)


# --------------------------------------------------
# 3. Split documents
# --------------------------------------------------

print("\n[3] Creating chunks...")

chunks = split_documents(
    cleaned_documents
)

print(
    f"Total chunks: {len(chunks)}"
)


# --------------------------------------------------
# 4. Use a small subset initially
# --------------------------------------------------

TEST_SIZE = min(
    100,
    len(chunks),
)

test_chunks = chunks[:TEST_SIZE]

print(
    f"\nUsing {len(test_chunks)} chunks "
    f"for initial FAISS test."
)


# --------------------------------------------------
# 5. Load embedding model
# --------------------------------------------------

print("\n[4] Loading embedding model...")

embedding_model = EmbeddingModel()


# --------------------------------------------------
# 6. Generate embeddings
# --------------------------------------------------

print("\n[5] Generating embeddings...")

texts = [
    chunk.page_content
    for chunk in test_chunks
]

embeddings = embedding_model.encode(
    texts
)

print(
    f"Embeddings generated: "
    f"{len(embeddings)}"
)

print(
    f"Embedding dimension: "
    f"{len(embeddings[0])}"
)


# --------------------------------------------------
# 7. Create FAISS store
# --------------------------------------------------

print("\n[6] Creating FAISS vector store...")

vector_store = FAISSVectorStore(
    dimension=384
)


# --------------------------------------------------
# 8. Add documents
# --------------------------------------------------

vector_store.add_documents(
    test_chunks,
    embeddings,
)

print(
    f"Vectors stored in FAISS: "
    f"{vector_store.index.ntotal}"
)


# --------------------------------------------------
# 9. Test similarity search
# --------------------------------------------------

query = (
    "What malware threats are associated "
    "with cyber attacks?"
)

print("\n[7] Testing semantic search...")

query_embedding = (
    embedding_model.encode_single(query)
)

results = vector_store.search(
    query_embedding,
    top_k=5,
)


print("\n========== SEARCH RESULTS ==========\n")


for rank, (document, score) in enumerate(
    results,
    start=1,
):

    print(
        f"--- Result {rank} "
        f"(score: {score:.4f}) ---"
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

    print()


# --------------------------------------------------
# 10. Save vector store
# --------------------------------------------------

print("\n[8] Saving FAISS vector store...")

vector_store.save(
    VECTOR_STORE_PATH
)

print(
    f"Vector store saved to: "
    f"{VECTOR_STORE_PATH}"
)


print("\n======================================")
print("VECTOR STORE TEST COMPLETED")
print("======================================")