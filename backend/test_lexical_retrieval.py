from app.rag.retriever import RAGRetriever
from app.rag.lexical_retriever import CTILexicalRetriever


print("=" * 80)
print("LIGHTWEIGHT LEXICAL RETRIEVAL TEST")
print("=" * 80)


query = "What ransomware attacks affected healthcare organizations in India?"

print("\nQUERY:")
print(query)


# ------------------------------------------------------
# Load the existing CTI documents
# ------------------------------------------------------

print("\n" + "-" * 80)
print("LOADING CTI DOCUMENTS")
print("-" * 80)

retriever = RAGRetriever(
    vector_store_path="data/vector_store"
)


documents = retriever.vector_store.documents

print("Documents loaded:", len(documents))


# ------------------------------------------------------
# Lexical retrieval
# ------------------------------------------------------

print("\n" + "-" * 80)
print("LEXICAL RETRIEVAL")
print("-" * 80)

results = CTILexicalRetriever.retrieve(
    query=query,
    documents=documents,
    top_k=5,
)


print("Lexical results:", len(results))


# ------------------------------------------------------
# Display results
# ------------------------------------------------------

print("\n" + "-" * 80)
print("TOP LEXICAL RESULTS")
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
        "Lexical Score:",
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
print("LEXICAL RETRIEVAL TEST COMPLETED")
print("=" * 80)