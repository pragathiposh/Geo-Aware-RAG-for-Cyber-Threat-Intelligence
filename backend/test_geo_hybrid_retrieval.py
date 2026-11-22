from app.rag.query_parser import CTIQueryParser
from app.rag.filter_builder import CTIFilterBuilder
from app.rag.hybrid_retriever import CTIHybridRetriever


print("=" * 80)
print("GEO-AWARE HYBRID RETRIEVAL TEST")
print("=" * 80)


# ------------------------------------------------------
# User query
# ------------------------------------------------------

query = (
    "What ransomware attacks affected "
    "North America?"
)

print("\nUSER QUERY:")
print(query)


# ------------------------------------------------------
# STEP 1 — Query parsing
# ------------------------------------------------------

print("\n" + "-" * 80)
print("STEP 1: QUERY PARSING")
print("-" * 80)

parser = CTIQueryParser()

parsed_query = parser.parse(
    query
)

print(
    "Threat Type:",
    parsed_query["threat_type"],
)

print(
    "Country:",
    parsed_query["country"],
)

print(
    "Industry:",
    parsed_query["industry"],
)

print(
    "Malware:",
    parsed_query["malware"],
)

print(
    "Attack ID:",
    parsed_query["attack_id"],
)

print(
    "Region:",
    parsed_query["region"],
)


# ------------------------------------------------------
# STEP 2 — Build filters
# ------------------------------------------------------

print("\n" + "-" * 80)
print("STEP 2: FILTER BUILDING")
print("-" * 80)

filters = CTIFilterBuilder.build_filters(
    parsed_query
)

print("Generated Filters:")

for field, value in filters.items():
    print(
        f"  {field}: {value}"
    )


# ------------------------------------------------------
# STEP 3 — Initialize hybrid retriever
# ------------------------------------------------------

print("\n" + "-" * 80)
print("STEP 3: INITIALIZING HYBRID RETRIEVER")
print("-" * 80)

retriever = CTIHybridRetriever(
    vector_store_path="data/vector_store",
    semantic_weight=0.7,
    lexical_weight=0.3,
)


# ------------------------------------------------------
# STEP 4 — Geo-aware hybrid retrieval
# ------------------------------------------------------

print("\n" + "-" * 80)
print("STEP 4: GEO-AWARE HYBRID RETRIEVAL")
print("-" * 80)

results = retriever.retrieve(
    query=query,
    top_k=5,
    filters=filters,
    candidate_k=20,
)


print(
    "\nFinal Results:",
    len(results),
)


# ------------------------------------------------------
# STEP 5 — Display results
# ------------------------------------------------------

print("\n" + "-" * 80)
print("TOP GEO-AWARE HYBRID RESULTS")
print("-" * 80)


for rank, (document, score) in enumerate(
    results,
    start=1,
):

    print(
        f"\nRESULT {rank}"
    )

    print(
        "Title:",
        document.metadata.get(
            "title",
            "Unknown",
        ),
    )

    print(f"Reranker Score: {score:.4f}")

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
print(
    "GEO-AWARE HYBRID RETRIEVAL TEST COMPLETED"
)
print("=" * 80)