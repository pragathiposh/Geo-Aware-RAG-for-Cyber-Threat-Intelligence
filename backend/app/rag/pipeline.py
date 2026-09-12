from typing import Any

from app.rag.retriever import RAGRetriever
from app.rag.prompt import CTIPromptBuilder
from app.rag.generator import CTIGenerator


class CTIRAGPipeline:
    """
    End-to-end baseline RAG pipeline for Cyber Threat Intelligence.

    Pipeline:

        User Query
            ↓
        RAG Retriever
            ↓
        Retrieved CTI Documents
            ↓
        Prompt Builder
            ↓
        Local LLM Generator
            ↓
        Final CTI Answer
    """

    def __init__(
        self,
        vector_store_path: str = "data/vector_store",
        model_name: str = "Qwen/Qwen2.5-1.5B-Instruct",
        top_k: int = 5,
        max_new_tokens: int = 300,
    ) -> None:

        self.top_k = top_k

        print("=" * 70)
        print("INITIALIZING CTI RAG PIPELINE")
        print("=" * 70)

        # --------------------------------------------------
        # Retriever
        # --------------------------------------------------

        print("\n[1] Initializing RAG retriever...")

        self.retriever = RAGRetriever(
            vector_store_path=vector_store_path
        )

        print("RAG retriever ready.")

        # --------------------------------------------------
        # Prompt Builder
        # --------------------------------------------------

        print("\n[2] Initializing prompt builder...")

        self.prompt_builder = CTIPromptBuilder()

        print("Prompt builder ready.")

        # --------------------------------------------------
        # LLM Generator
        # --------------------------------------------------

        print("\n[3] Initializing CTI generator...")

        self.generator = CTIGenerator(
            model_name=model_name,
            max_new_tokens=max_new_tokens,
        )

        print("CTI generator ready.")

        print("\nCTI RAG pipeline initialized successfully.")

    # ------------------------------------------------------
    # Run complete RAG pipeline
    # ------------------------------------------------------

    def query(
        self,
        user_query: str,
        top_k: int | None = None,
        max_new_tokens: int | None = None,
    ) -> dict[str, Any]:

        if not user_query or not user_query.strip():
            raise ValueError("User query cannot be empty.")

        retrieval_k = (
            top_k
            if top_k is not None
            else self.top_k
        )

        print("\n" + "=" * 70)
        print("RUNNING CTI RAG PIPELINE")
        print("=" * 70)

        # --------------------------------------------------
        # Step 1: Retrieve CTI evidence
        # --------------------------------------------------

        print("\n[1] Retrieving CTI evidence...")

        retrieved_documents = self.retriever.retrieve(
            query=user_query,
            top_k=retrieval_k,
        )

        print(
            f"Retrieved {len(retrieved_documents)} "
            "CTI documents."
        )

        # --------------------------------------------------
        # Step 2: Build grounded prompt
        # --------------------------------------------------

        print("\n[2] Building evidence-grounded prompt...")

        prompt = self.prompt_builder.build_prompt(
            query=user_query,
            documents=retrieved_documents,
        )

        print("Prompt built successfully.")

        # --------------------------------------------------
        # Step 3: Generate answer
        # --------------------------------------------------

        print("\n[3] Generating CTI answer...")
        print("Please wait...")

        answer = self.generator.generate(
            prompt=prompt,
            max_new_tokens=max_new_tokens,
        )

        print("Answer generated successfully.")

        # --------------------------------------------------
        # Step 4: Return complete result
        # --------------------------------------------------

        return {
            "query": user_query,
            "answer": answer,
            "retrieved_documents": retrieved_documents,
            "prompt": prompt,
        }