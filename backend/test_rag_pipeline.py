from app.rag.pipeline import CTIRAGPipeline


print("=" * 70)
print("END-TO-END CTI RAG PIPELINE TEST")
print("=" * 70)


# ----------------------------------------------------------
# 1. Initialize pipeline
# ----------------------------------------------------------

print("\n[1] Initializing complete RAG pipeline...")

pipeline = CTIRAGPipeline(
    vector_store_path="data/vector_store",
    model_name="Qwen/Qwen2.5-1.5B-Instruct",
    top_k=5,
    max_new_tokens=250,
)

print("\n[2] Pipeline ready.")


# ----------------------------------------------------------
# 2. User query
# ----------------------------------------------------------

query = (
    "What ransomware threats are associated "
    "with cyber attacks?"
)

print("\n[3] User Query:")
print(query)


# ----------------------------------------------------------
# 3. Run complete RAG pipeline
# ----------------------------------------------------------

print("\n[4] Running complete RAG pipeline...")

result = pipeline.query(
    user_query=query,
)


# ----------------------------------------------------------
# 4. Display answer
# ----------------------------------------------------------

print("\n")
print("=" * 70)
print("FINAL CTI ANSWER")
print("=" * 70)

print(result["answer"])


# ----------------------------------------------------------
# 5. Display retrieved evidence
# ----------------------------------------------------------

print("\n")
print("=" * 70)
print("RETRIEVED CTI SOURCES")
print("=" * 70)

for rank, (document, score) in enumerate(
    result["retrieved_documents"],
    start=1,
):

    print(f"\n[{rank}] {document.metadata.get('title', 'Unknown')}")
    print(f"Similarity Score: {score:.4f}")
    print(
        f"Countries: "
        f"{document.metadata.get('countries', 'Unknown')}"
    )
    print(
        f"Malware: "
        f"{document.metadata.get('malware_families', 'Unknown')}"
    )
    print(
        f"Industries: "
        f"{document.metadata.get('industries', 'Unknown')}"
    )


print("\n")
print("=" * 70)
print("END-TO-END RAG TEST COMPLETED")
print("=" * 70)