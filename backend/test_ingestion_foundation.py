import pandas as pd

from app.rag.loader import load_canonical_cti_csv, load_cti_csv
from app.preprocessing.splitter import split_documents


def test_csv_loader_cleans_missing_values_and_keeps_row_provenance(tmp_path):
    csv_path = tmp_path / "otx.csv"
    pd.DataFrame([
        {"Pulse_ID": None, "Title": None, "Description": " Evidence ", "Countries": None},
        {"Pulse_ID": "skip", "Description": None},
    ]).to_csv(csv_path, index=False)

    documents = load_cti_csv(csv_path)

    assert len(documents) == 1
    document = documents[0]
    assert "nan" not in document.page_content.lower()
    assert document.metadata["title"] == ""
    assert document.metadata["countries"] == ""
    assert document.metadata["source_record_id"] == "otx:row:1"
    assert document.metadata["source_row"] == 1
    assert document.metadata["source"] == "otx.csv"


def test_canonical_loader_normalizes_and_preserves_geo_association(tmp_path):
    csv_path = tmp_path / "otx.csv"
    pd.DataFrame([{
        "Pulse_ID": "pulse-1",
        "Title": "Example",
        "Description": "Incident report",
        "Countries": "USA, Unknown",
        "Industries": "health",
        "Attack_IDs": "t1486,invalid",
        "Malware_Families": "Example, Unknown",
        "Tags": "malware, ransomware",
    }]).to_csv(csv_path, index=False)

    documents = load_canonical_cti_csv(csv_path)
    metadata = documents[0].metadata

    assert metadata["countries"] == ["United States"]
    assert metadata["geography_semantics"] == "source_association_only"
    assert metadata["industries"] == ["Healthcare"]
    assert metadata["attack_ids"] == ["T1486"]
    assert metadata["malware_families"] == ["Example"]
    assert metadata["canonical_tags"] == ["malware", "ransomware"]
    assert metadata["source_record_id"] == "pulse-1"
    assert '"record_id": "pulse-1"' in metadata["canonical_cti"]


def test_canonical_loader_calls_attack_enricher(tmp_path):
    csv_path = tmp_path / "otx.csv"
    pd.DataFrame([{
        "Pulse_ID": "pulse-2", "Description": "Evidence", "Attack_IDs": "T1486"
    }]).to_csv(csv_path, index=False)

    class Enricher:
        called = False

        def enrich_record(self, record):
            self.called = True
            technique = record.attack_techniques[0].model_copy(
                update={"name": "Data Encrypted for Impact"}
            )
            return record.model_copy(update={"attack_techniques": [technique]})

    enricher = Enricher()
    metadata = load_canonical_cti_csv(csv_path, enricher)[0].metadata

    assert enricher.called
    assert metadata["attack_enrichment"][0]["name"] == "Data Encrypted for Impact"


def test_canonical_record_uses_provenance_id_when_pulse_id_missing(tmp_path):
    csv_path = tmp_path / "otx.csv"
    pd.DataFrame([{"Description": "Evidence"}]).to_csv(csv_path, index=False)

    metadata = load_canonical_cti_csv(csv_path)[0].metadata

    assert metadata["record_id"] == "otx:row:1"


def test_splitter_assigns_stable_unique_chunk_ids():
    from langchain_core.documents import Document

    source = Document(
        page_content="word " * 1000,
        metadata={"source_record_id": "pulse-3"},
    )
    chunks = split_documents([source], chunk_size=100, chunk_overlap=10)

    assert len(chunks) > 1
    ids = [chunk.metadata["chunk_id"] for chunk in chunks]
    assert ids == [f"pulse-3:chunk:{index}" for index in range(len(chunks))]
