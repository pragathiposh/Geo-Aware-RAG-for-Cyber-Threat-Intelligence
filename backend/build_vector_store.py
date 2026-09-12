from app.rag.loader import load_cti_csv
from app.preprocessing.cleaner import clean_documents
from app.preprocessing.splitter import split_documents
from app.embeddings.model import EmbeddingModel
from app.vector_db.faiss_store import FAISSVectorStore


CSV_PATH = "data/raw/csv/1_otx_threat_intel.csv"
VECTOR_STORE_PATH = "data/vector_store"

EMBEDDING_DIMENSION = 384


print("=" * 60)
print("BUILDING FULL CTI VECTOR STORE")
print("=" * 60)


# --------------------------------------------------
# 1. Load documents
# --------------------------------------------------

print("\n[1/6] Loading CTI documents...")

documents = load_cti_csv(
    CSV_PATH
)

print(
    f"Loaded {len(documents)} documents."
)


# --------------------------------------------------
# 2. Clean documents
# --------------------------------------------------

print("\n[2/6] Cleaning documents...")

cleaned_documents = clean_documents(
    documents
)

print(
    f"Cleaned documents: "
    f"{len(cleaned_documents)}"
)


# --------------------------------------------------
# 3. Create chunks
# --------------------------------------------------

print("\n[3/6] Creating chunks...")

chunks = split_documents(
    cleaned_documents
)

print(
    f"Generated chunks: "
    f"{len(chunks)}"
)


if not chunks:
    raise RuntimeError(
        "No chunks were generated."
    )


# --------------------------------------------------
# 4. Load embedding model
# --------------------------------------------------

print("\n[4/6] Loading embedding model...")

embedding_model = EmbeddingModel()

print("Embedding model ready.")


# --------------------------------------------------
# 5. Generate embeddings
# --------------------------------------------------

print("\n[5/6] Generating embeddings...")

texts = [
    chunk.page_content
    for chunk in chunks
]

embeddings = embedding_model.encode(
    texts
)

print(
    f"Generated {len(embeddings)} embeddings."
)

print(
    f"Embedding dimension: "
    f"{len(embeddings[0])}"
)


# --------------------------------------------------
# 6. Build FAISS index
# --------------------------------------------------

print("\n[6/6] Building FAISS vector store...")

vector_store = FAISSVectorStore(
    dimension=EMBEDDING_DIMENSION
)

vector_store.add_documents(
    chunks,
    embeddings
)

print(
    f"Vectors stored: "
    f"{vector_store.index.ntotal}"
)


# --------------------------------------------------
# Save
# --------------------------------------------------

print("\nSaving vector store...")

vector_store.save(
    VECTOR_STORE_PATH
)

print(
    f"Vector store saved to: "
    f"{VECTOR_STORE_PATH}"
)


print("\n" + "=" * 60)
print("FULL VECTOR STORE BUILD COMPLETED")
print("=" * 60)