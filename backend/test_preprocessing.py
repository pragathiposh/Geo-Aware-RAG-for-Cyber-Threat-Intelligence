from app.rag.loader import load_cti_csv
from app.preprocessing.cleaner import clean_documents
from app.preprocessing.splitter import split_documents


CSV_PATH = "data/raw/csv/1_otx_threat_intel.csv"


print("======================================")
print("CTI PREPROCESSING TEST")
print("======================================")

# Step 1: Load documents
documents = load_cti_csv(CSV_PATH)

print("\nDocuments loaded:", len(documents))


# Step 2: Clean documents
cleaned_documents = clean_documents(documents)

print("Documents after cleaning:", len(cleaned_documents))


# Step 3: Split into chunks
chunks = split_documents(cleaned_documents)

print("Total chunks generated:", len(chunks))


# Step 4: Display sample chunk
if chunks:

    print("\n========== SAMPLE CHUNK ==========\n")

    print(chunks[0].page_content)

    print("\n========== CHUNK METADATA ==========\n")

    print(chunks[0].metadata)

    print("\n========== CHUNK LENGTH ==========\n")

    print(len(chunks[0].page_content))

    if chunks:

        lengths = [
            len(chunk.page_content)
            for chunk in chunks
        ]

        print("\n========== CHUNK STATISTICS ==========\n")

        print("Minimum length:", min(lengths))
        print("Maximum length:", max(lengths))
        print(
            "Average length:",
            round(sum(lengths) / len(lengths), 2)
        )