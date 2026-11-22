from app.rag.query_parser import CTIQueryParser


print("=" * 70)
print("CTI QUERY PARSER TEST")
print("=" * 70)


parser = CTIQueryParser()


test_queries = [
    "What ransomware attacks affected healthcare organizations in the United States?",
    "Tell me about Medusa ransomware attacks in India.",
    "Which ransomware threats were reported in the US?",
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

    print("\nQuery:")
    print(query)

    result = parser.parse(query)

    print("\nExtracted Information:")

    for key, value in result.items():

        print(
            f"{key}: {value}"
        )


print("\n" + "=" * 70)
print("QUERY PARSER TEST COMPLETED")
print("=" * 70)