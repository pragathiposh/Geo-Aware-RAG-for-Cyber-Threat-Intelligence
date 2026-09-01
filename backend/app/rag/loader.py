from pathlib import Path

import pandas as pd
from langchain_core.documents import Document


def load_cti_csv(file_path: str) -> list[Document]:
    """
    Load cybersecurity threat intelligence records from a CSV file
    and convert each valid record into a LangChain Document.
    """

    path = Path(file_path)

    if not path.exists():
        raise FileNotFoundError(f"CSV file not found: {file_path}")

    df = pd.read_csv(path)

    documents: list[Document] = []

    for _, row in df.iterrows():

        description = str(row.get("Description", "")).strip()

        # Skip records where the description is missing
        if not description or description.lower() == "nan":
            continue

        content = f"""
Title: {row.get("Title", "")}

Description:
{description}

Malware Families:
{row.get("Malware_Families", "")}

Attack IDs:
{row.get("Attack_IDs", "")}

Industries:
{row.get("Industries", "")}

Countries:
{row.get("Countries", "")}

Tags:
{row.get("Tags", "")}
""".strip()

        metadata = {
            "pulse_id": str(row.get("Pulse_ID", "")),
            "title": str(row.get("Title", "")),
            "author": str(row.get("Author", "")),
            "created": str(row.get("Created", "")),
            "modified": str(row.get("Modified", "")),
            "tlp": str(row.get("TLP", "")),
            "malware_families": str(row.get("Malware_Families", "")),
            "attack_ids": str(row.get("Attack_IDs", "")),
            "industries": str(row.get("Industries", "")),
            "countries": str(row.get("Countries", "")),
            "source": path.name,
        }

        documents.append(
            Document(
                page_content=content,
                metadata=metadata,
            )
        )

    return documents