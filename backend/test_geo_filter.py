from langchain_core.documents import Document

from app.rag.metadata_filter import CTIMetadataFilter


print("=" * 80)
print("GEO METADATA FILTER TEST")
print("=" * 80)


documents = [
    Document(
        page_content="US ransomware attack",
        metadata={
            "countries": "United States",
            "title": "US Ransomware Attack",
        },
    ),
    Document(
        page_content="Canada ransomware attack",
        metadata={
            "countries": "Canada",
            "title": "Canada Ransomware Attack",
        },
    ),
    Document(
        page_content="Australia ransomware attack",
        metadata={
            "countries": "Australia",
            "title": "Australia Ransomware Attack",
        },
    ),
    Document(
        page_content="US and Canada ransomware attack",
        metadata={
            "countries": "United States, Canada",
            "title": "US Canada Ransomware Attack",
        },
    ),
]


filters = {
    "countries": "United States|Canada"
}


print("\nFilter:")
print(filters)


filtered_documents = CTIMetadataFilter.filter_documents(
    documents=documents,
    filters=filters,
)


print("\n" + "-" * 80)
print("MATCHED DOCUMENTS")
print("-" * 80)


for document in filtered_documents:
    print(
        "Title:",
        document.metadata.get("title")
    )

    print(
        "Countries:",
        document.metadata.get("countries")
    )


print("\nTotal Matches:", len(filtered_documents))


print("\n" + "=" * 80)
print("GEO METADATA FILTER TEST COMPLETED")
print("=" * 80)