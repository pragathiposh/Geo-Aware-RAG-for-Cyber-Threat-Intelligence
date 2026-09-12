from app.rag.retriever import RAGRetriever
from app.rag.prompt import CTIPromptBuilder


VECTOR_STORE_PATH = "data/vector_store"


print("=" * 70)
print("CTI PROMPT BUILDER TEST")
print("=" * 70)


# --------------------------------------------------
# 1. Initialize retriever
# --------------------------------------------------

print("\n[1] Initializing retriever...")

retriever = RAGRetriever(
    vector_store_path=VECTOR_STORE_PATH
)

print("Retriever ready.")


# --------------------------------------------------
# 2. Create prompt builder
# --------------------------------------------------

print("\n[2] Initializing prompt builder...")

prompt_builder = CTIPromptBuilder()

print("Prompt builder ready.")


# --------------------------------------------------
# 3. Query
# --------------------------------------------------

query = (
    "What ransomware threats are associated "
    "with cyber attacks?"
)

print("\n[3] User query:")
print(query)


# --------------------------------------------------
# 4. Retrieve CTI evidence
# --------------------------------------------------

print("\n[4] Retrieving CTI evidence...")

results = retriever.retrieve(
    query=query,
    top_k=5,
)

print(
    f"Retrieved {len(results)} documents."
)


# --------------------------------------------------
# 5. Build prompt
# --------------------------------------------------

print("\n[5] Building prompt...")

prompt = prompt_builder.build_prompt(
    query=query,
    documents=results,
)


# --------------------------------------------------
# 6. Display prompt
# --------------------------------------------------

print("\n")
print("=" * 70)
print("GENERATED PROMPT")
print("=" * 70)

print(prompt)


# --------------------------------------------------
# 7. Final status
# --------------------------------------------------

print("\n")
print("=" * 70)
print("PROMPT BUILDER TEST COMPLETED")
print("=" * 70)