from app.rag.retriever import RAGRetriever


print("=" * 70)
print("METADATA-AWARE RAG RETRIEVAL TEST")
print("=" * 70)


# ------------------------------------------------------
# 1. Load retriever
# ------------------------------------------------------

print("\n[1] Loading RAG retriever...")

retriever = RAGRetriever(
    vector_store_path="data/vector_store"
)

print("Retriever ready.")


# ------------------------------------------------------
# 2. Define test query
# ------------------------------------------------------

query = (
    "What ransomware attacks affected "
    "healthcare organizations in the United States?"
)


print("\n[2] Query:")
print(query)


# ------------------------------------------------------
# 3. Define metadata filters
# ------------------------------------------------------

filters = {
    "countries": "United States",
    "industries": "Healthcare",
}


print("\n[3] Metadata filters:")
print(filters)


# ------------------------------------------------------
# 4. Retrieve documents
# ------------------------------------------------------

print("\n[4] Running metadata-aware retrieval...")

results = retriever.retrieve(
    query=query,
    top_k=5,
    filters=filters,
    candidate_k=20,
)


print(
    f"\nFinal retrieved documents: "
    f"{len(results)}"
)


# ------------------------------------------------------
# 5. Display results
# ------------------------------------------------------

print("\n")
print("=" * 70)
print("RETRIEVED CTI DOCUMENTS")
print("=" * 70)


for rank, (document, score) in enumerate(
    results,
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
        "Similarity Score:",
        round(score, 4),
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

    print(
        "ATT&CK:",
        document.metadata.get(
            "attack_ids",
            "Unknown",
        ),
    )


print("\n")
print("=" * 70)
print("METADATA-AWARE RETRIEVAL TEST COMPLETED")
print("=" * 70)