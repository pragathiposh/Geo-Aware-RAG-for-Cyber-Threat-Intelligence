from app.rag.hybrid_retriever import CTIHybridRetriever


print("=" * 80)
print("LIGHTWEIGHT HYBRID RETRIEVAL TEST")
print("=" * 80)


query = "What ransomware attacks affected healthcare organizations in India?"

print("\nQUERY:")
print(query)


# ------------------------------------------------------
# Initialize hybrid retriever
# ------------------------------------------------------

print("\n" + "-" * 80)
print("INITIALIZING HYBRID RETRIEVER")
print("-" * 80)

retriever = CTIHybridRetriever(
    vector_store_path="data/vector_store",
    semantic_weight=0.7,
    lexical_weight=0.3,
)


# ------------------------------------------------------
# Retrieve
# ------------------------------------------------------

print("\n" + "-" * 80)
print("HYBRID RETRIEVAL")
print("-" * 80)

results = retriever.retrieve(
    query=query,
    top_k=5,
    candidate_k=20,
)


print("\nFinal Results:", len(results))


# ------------------------------------------------------
# Display results
# ------------------------------------------------------

print("\n" + "-" * 80)
print("TOP HYBRID RESULTS")
print("-" * 80)


for rank, (document, score) in enumerate(
    results,
    start=1,
):

    print(f"\nRESULT {rank}")

    print(
        "Title:",
        document.metadata.get(
            "title",
            "Unknown",
        ),
    )

    print(
        "Hybrid Score:",
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
        "ATT&CK IDs:",
        document.metadata.get(
            "attack_ids",
            "Unknown",
        ),
    )


print("\n")
print("=" * 80)
print("HYBRID RETRIEVAL TEST COMPLETED")
print("=" * 80)