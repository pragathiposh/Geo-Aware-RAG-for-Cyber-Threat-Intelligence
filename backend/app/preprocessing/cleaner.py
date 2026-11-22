import re

from langchain_core.documents import Document


def clean_text(text: str) -> str:
    """
    Clean and normalize text while preserving
    cybersecurity-related information.
    """

    if not text:
        return ""

    # Normalize line endings
    text = text.replace("\r\n", "\n")
    text = text.replace("\r", "\n")

    # Remove excessive spaces
    text = re.sub(r"[ \t]+", " ", text)

    # Remove excessive blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)

    return text.strip()


def clean_documents(
    documents: list[Document],
) -> list[Document]:
    """
    Clean the content of each LangChain Document.
    """

    cleaned_documents = []

    for document in documents:

        cleaned_content = clean_text(
            document.page_content
        )

        if not cleaned_content:
            continue

        cleaned_documents.append(
            Document(
                page_content=cleaned_content,
                metadata=document.metadata.copy(),
            )
        )

    return cleaned_documents