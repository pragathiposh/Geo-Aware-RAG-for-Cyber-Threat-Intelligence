"""Manual metadata-aware retrieval demo (kept inert during pytest collection)."""


def run_demo():
    from app.rag.query_parser import CTIQueryParser
    from app.rag.filter_builder import CTIFilterBuilder
    from app.rag.retriever import RAGRetriever

    print("=" * 70)
    print("AUTOMATIC METADATA-AWARE RETRIEVAL TEST")
    print("=" * 70)
    parser = CTIQueryParser()
    retriever = RAGRetriever(vector_store_path="data/vector_store")
    query = "What ransomware attacks affected healthcare organizations in the United States?"
    parsed_query = parser.parse(query)
    filters = CTIFilterBuilder.build_filters(parsed_query)
    results = retriever.retrieve(query=query, top_k=5, filters=filters, candidate_k=20)
    print("Parsed Query:", parsed_query)
    print("Generated Filters:", filters)
    print("Final retrieved documents:", len(results))
    for rank, (document, score) in enumerate(results, start=1):
        print(f"\n[{rank}] {document.metadata.get('title', 'Unknown')}")
        print("Relevance score:", round(score, 4))
        for field in ("countries", "industries", "malware_families", "attack_ids"):
            print(f"{field}:", document.metadata.get(field, "Unknown"))
    print("\nAUTOMATIC METADATA-AWARE RETRIEVAL DEMO COMPLETED")


if __name__ == "__main__":
    run_demo()
