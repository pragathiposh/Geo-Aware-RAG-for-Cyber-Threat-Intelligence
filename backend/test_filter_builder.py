from app.rag.query_parser import CTIQueryParser
from app.rag.filter_builder import CTIFilterBuilder


print("=" * 70)
print("CTI FILTER BUILDER TEST")
print("=" * 70)


parser = CTIQueryParser()


test_queries = [
    "What ransomware attacks affected healthcare organizations in the United States?",
    "Tell me about Medusa ransomware attacks in India.",
    "What attacks used T1486?",
    "Which threats affected financial organizations in the US?",
    "Tell me about Play ransomware in Australia.",
]


for index, query in enumerate(
    test_queries,
    start=1,
):

    print("\n" + "-" * 70)

    print(f"TEST {index}")

    print("\nOriginal Query:")
    print(query)

    parsed_query = parser.parse(
        query
    )

    print("\nParsed Query:")

    for key, value in parsed_query.items():
        print(
            f"{key}: {value}"
        )

    filters = CTIFilterBuilder.build_filters(
        parsed_query
    )

    print("\nGenerated Metadata Filters:")

    if filters:

        for key, value in filters.items():
            print(
                f"{key}: {value}"
            )

    else:

        print("No metadata filters generated.")


print("\n")
print("=" * 70)
print("FILTER BUILDER TEST COMPLETED")
print("=" * 70)