from langchain_core.documents import Document

from app.rag.retriever import RAGRetriever


print("=" * 80)
print("RETRIEVAL DEDUPLICATION TEST")
print("=" * 80)


# Create a retriever instance without running its full __init__.
retriever = RAGRetriever.__new__(RAGRetriever)


documents = [
    Document(
        page_content="Chunk 1 of Pulse A",
        metadata={
            "pulse_id": "PULSE_A",
            "title": "Threat Report A",
        },
    ),
    Document(
        page_content="Chunk 2 of Pulse A",
        metadata={
            "pulse_id": "PULSE_A",
            "title": "Threat Report A",
        },
    ),
    Document(
        page_content="Chunk 1 of Pulse B",
        metadata={
            "pulse_id": "PULSE_B",
            "title": "Threat Report B",
        },
    ),
    Document(
        page_content="Chunk 1 of Pulse C",
        metadata={
            "pulse_id": "PULSE_C",
            "title": "Threat Report C",
        },
    ),
]


print("\nOriginal candidate count:", len(documents))


# Simulate the deduplication logic.
unique_candidates = []
seen_documents = set()

for document in documents:

    document_id = document.metadata.get("pulse_id")

    if document_id is None:
        document_id = document.metadata.get("title")

    if document_id is None:
        document_id = document.page_content

    document_key = str(document_id).strip().lower()

    if not document_key:
        continue

    if document_key in seen_documents:
        continue

    seen_documents.add(document_key)

    unique_candidates.append(document)


print("Unique document count:", len(unique_candidates))


print("\n" + "-" * 80)
print("UNIQUE DOCUMENTS")
print("-" * 80)

for index, document in enumerate(unique_candidates, start=1):

    print(
        f"{index}.",
        document.metadata.get("title"),
        "| Pulse ID:",
        document.metadata.get("pulse_id"),
    )


print("\n" + "=" * 80)
print("RETRIEVAL DEDUPLICATION TEST COMPLETED")
print("=" * 80)