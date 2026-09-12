from app.rag.pipeline import CTIRAGPipeline


print("=" * 70)
print("GEO-AWARE CYBER THREAT INTELLIGENCE ASSISTANT")
print("=" * 70)

print("\nInitializing system...")
print("Please wait...\n")


# ----------------------------------------------------------
# Initialize RAG pipeline once
# ----------------------------------------------------------

pipeline = CTIRAGPipeline(
    vector_store_path="data/vector_store",
    model_name="Qwen/Qwen2.5-1.5B-Instruct",
    top_k=5,
    max_new_tokens=200,
)


print("\n" + "=" * 70)
print("SYSTEM READY")
print("=" * 70)

print("\nYou can now ask cybersecurity questions.")
print("Type 'exit' or 'quit' to stop.\n")


# ----------------------------------------------------------
# Interactive query loop
# ----------------------------------------------------------

while True:

    try:
        user_query = input("You: ").strip()

    except (KeyboardInterrupt, EOFError):
        print("\n\nExiting CTI assistant.")
        break

    # ------------------------------------------------------
    # Exit commands
    # ------------------------------------------------------

    if user_query.lower() in {"exit", "quit"}:
        print("\nExiting CTI assistant.")
        break

    # ------------------------------------------------------
    # Empty query
    # ------------------------------------------------------

    if not user_query:
        print("Please enter a cybersecurity question.\n")
        continue

    # ------------------------------------------------------
    # Run RAG pipeline
    # ------------------------------------------------------

    try:

        print("\nAnalyzing your question...")
        print("Retrieving relevant CTI evidence...")

        result = pipeline.query(
            user_query=user_query,
        )

        # --------------------------------------------------
        # Display answer
        # --------------------------------------------------

        print("\n" + "=" * 70)
        print("CTI ASSISTANT")
        print("=" * 70)

        print("\n" + result["answer"])

        # --------------------------------------------------
        # Display sources
        # --------------------------------------------------

        print("\n" + "-" * 70)
        print("RETRIEVED SOURCES")
        print("-" * 70)

        for rank, (document, score) in enumerate(
            result["retrieved_documents"],
            start=1,
        ):

            title = document.metadata.get(
                "title",
                "Unknown",
            )

            print(
                f"\n[{rank}] {title}"
            )

            print(
                f"Similarity: {score:.4f}"
            )

    except Exception as error:

        print("\nAn error occurred while processing the query.")

        print(f"Error: {error}")

    print("\n")