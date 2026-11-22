from app.rag.query_parser import CTIQueryParser
from app.rag.filter_builder import CTIFilterBuilder
from app.rag.retriever import RAGRetriever


print("=" * 80)
print("END-TO-END GEO-AWARE RETRIEVAL TEST")
print("=" * 80)

query = "What ransomware attacks affected North America?"

print("\nUSER QUERY:")
print(query)

# ---------------------------------------------------------
# STEP 1: Parse the query
# ---------------------------------------------------------

parser = CTIQueryParser()
parsed_query = parser.parse(query)

print("\n" + "-" * 80)
print("STEP 1: QUERY PARSING")
print("-" * 80)

print("Threat Type:", parsed_query["threat_type"])
print("Country:", parsed_query["country"])
print("Industry:", parsed_query["industry"])
print("Malware:", parsed_query["malware"])
print("Attack ID:", parsed_query["attack_id"])
print("Region:", parsed_query["region"])


# ---------------------------------------------------------
# STEP 2: Build metadata filters
# ---------------------------------------------------------

filters = CTIFilterBuilder.build_filters(parsed_query)

print("\n" + "-" * 80)
print("STEP 2: FILTER BUILDING")
print("-" * 80)

print("Generated Filters:")
for field, value in filters.items():
    print(f"  {field}: {value}")


# ---------------------------------------------------------
# STEP 3: Retrieve documents
# ---------------------------------------------------------

print("\n" + "-" * 80)
print("STEP 3: GEO-AWARE RETRIEVAL")
print("-" * 80)

retriever = RAGRetriever(
    vector_store_path="data/vector_store"
)

results = retriever.retrieve(
    query=query,
    top_k=5,
    filters=filters,
    candidate_k=20,
)

print(f"\nFinal Results: {len(results)}")


# ---------------------------------------------------------
# STEP 4: Display retrieved CTI records
# ---------------------------------------------------------

print("\n" + "-" * 80)
print("STEP 4: RETRIEVED CTI RECORDS")
print("-" * 80)

for rank, (document, score) in enumerate(results, start=1):

    print(f"\nRESULT {rank}")
    print("Title:", document.metadata.get("title", "Unknown"))
    print("Similarity Score:", round(score, 4))
    print("Countries:", document.metadata.get("countries", "Unknown"))
    print(
        "Malware:",
        document.metadata.get("malware_families", "Unknown")
    )
    print(
        "Industries:",
        document.metadata.get("industries", "Unknown")
    )
    print(
        "ATT&CK IDs:",
        document.metadata.get("attack_ids", "Unknown")
    )


print("\n")
print("=" * 80)
print("GEO-AWARE RETRIEVAL TEST COMPLETED")
print("=" * 80)