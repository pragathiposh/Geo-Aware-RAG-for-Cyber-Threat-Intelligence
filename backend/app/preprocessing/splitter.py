from langchain_core.documents import Document
from langchain_text_splitters import RecursiveCharacterTextSplitter


def split_documents(
    documents: list[Document],
    chunk_size: int = 800,
    chunk_overlap: int = 120,
) -> list[Document]:
    """
    Split CTI documents into overlapping chunks.

    Chunk size and overlap are intentionally moderate
    for CPU-based development.
    """

    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=chunk_overlap,
        separators=[
            "\n\n",
            "\n",
            ". ",
            " ",
            "",
        ],
    )

    chunks = splitter.split_documents(documents)
    per_record: dict[str, int] = {}
    for chunk in chunks:
        metadata = chunk.metadata
        record_id = str(
            metadata.get("source_record_id")
            or metadata.get("record_id")
            or metadata.get("pulse_id")
            or "unknown-record"
        )
        chunk_number = per_record.get(record_id, 0)
        per_record[record_id] = chunk_number + 1
        metadata["chunk_id"] = f"{record_id}:chunk:{chunk_number}"
    return chunks
