"""Model-free pipeline wiring test plus an opt-in local-model demo."""

from langchain_core.documents import Document

from app.rag.pipeline import CTIRAGPipeline


def test_pipeline_routes_query_through_retriever_prompt_and_generator():
    pipeline = CTIRAGPipeline.__new__(CTIRAGPipeline)
    pipeline.top_k = 3

    class Retriever:
        def retrieve(self, query, top_k):
            assert query == "What does the report say?"
            assert top_k == 3
            return [(Document(page_content="Evidence", metadata={"title": "Report"}), 0.8)]

    class PromptBuilder:
        def build_prompt(self, query, documents):
            assert query == "What does the report say?"
            assert len(documents) == 1
            return "grounded prompt"

    class Generator:
        def generate(self, prompt, max_new_tokens=None):
            assert prompt == "grounded prompt"
            return "grounded answer"

    pipeline.retriever = Retriever()
    pipeline.prompt_builder = PromptBuilder()
    pipeline.generator = Generator()

    result = pipeline.query("What does the report say?")

    assert result["answer"] == "grounded answer"
    assert result["prompt"] == "grounded prompt"
    assert len(result["retrieved_documents"]) == 1


def run_local_model_demo():
    """Explicitly run the full local-model example outside pytest collection."""
    pipeline = CTIRAGPipeline(
        vector_store_path="data/vector_store",
        model_name="Qwen/Qwen2.5-1.5B-Instruct",
        top_k=5,
        max_new_tokens=250,
    )
    result = pipeline.query(
        "What ransomware threats are associated with cyber attacks?"
    )
    print(result["answer"])
    for rank, (document, score) in enumerate(result["retrieved_documents"], start=1):
        print(rank, document.metadata.get("title", "Unknown"), score)


if __name__ == "__main__":
    run_local_model_demo()
