from app.rag.retriever import RAGRetriever


print("=" * 70)
print("RAG RETRIEVER TEST")
print("=" * 70)


# --------------------------------------------------
# 1. Initialize retriever
# --------------------------------------------------

print("\n[1] Initializing RAG retriever...")

retriever = RAGRetriever(
    vector_store_path="data/vector_store"
)

print("Retriever initialized successfully.")


# --------------------------------------------------
# 2. Test query
# --------------------------------------------------

query = (
    "What ransomware threats are associated "
    "with cyber attacks?"
)

print("\n[2] Query:")
print(query)


# --------------------------------------------------
# 3. Retrieve documents
# --------------------------------------------------

print("\n[3] Retrieving relevant CTI documents...")

results = retriever.retrieve(
    query=query,
    top_k=5,
)


# --------------------------------------------------
# 4. Display results
# --------------------------------------------------

print("\n")
print("=" * 70)
print("RETRIEVAL RESULTS")
print("=" * 70)

print(
    f"\nRetrieved documents: {len(results)}"
)


for rank, (document, score) in enumerate(
    results,
    start=1,
):

    print("\n" + "-" * 70)

    print(f"Result {rank}")

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

    print("\nContent preview:")

    print(
        document.page_content[:500]
    )


print("\n")
print("=" * 70)
print("RAG RETRIEVER TEST COMPLETED")
print("=" * 70)