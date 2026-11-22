from app.rag.retriever import RAGRetriever
from app.rag.metadata_filter import CTIMetadataFilter


print("=" * 70)
print("CTI METADATA FILTER TEST")
print("=" * 70)


# ----------------------------------------------------------
# 1. Load retriever
# ----------------------------------------------------------

print("\n[1] Loading RAG retriever...")

retriever = RAGRetriever(
    vector_store_path="data/vector_store"
)

print("Retriever ready.")


# ----------------------------------------------------------
# 2. Retrieve documents
# ----------------------------------------------------------

query = "ransomware attacks"

print("\n[2] Retrieving documents...")
print(f"Query: {query}")

results = retriever.retrieve(
    query=query,
    top_k=20,
)

print(
    f"Retrieved {len(results)} documents "
    "before metadata filtering."
)


# ----------------------------------------------------------
# 3. Extract documents
# ----------------------------------------------------------

documents = [
    document
    for document, score in results
]


# ----------------------------------------------------------
# 4. Apply country filter
# ----------------------------------------------------------

country_filter = {
    "countries": "United States"
}

print("\n[3] Applying country filter:")
print(country_filter)

filtered_documents = CTIMetadataFilter.filter_documents(
    documents=documents,
    filters=country_filter,
)

print(
    f"Documents after country filtering: "
    f"{len(filtered_documents)}"
)


# ----------------------------------------------------------
# 5. Display results
# ----------------------------------------------------------

print("\n")
print("=" * 70)
print("FILTERED DOCUMENTS")
print("=" * 70)

for rank, document in enumerate(
    filtered_documents,
    start=1,
):

    print(f"\n[{rank}]")

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
        "Industries:",
        document.metadata.get(
            "industries",
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


print("\n")
print("=" * 70)
print("METADATA FILTER TEST COMPLETED")
print("=" * 70)