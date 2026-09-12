from typing import Any

import torch
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
)


class CTIGenerator:
    """
    Local LLM generator for the Cyber Threat Intelligence
    RAG system.

    Responsibilities:
        1. Load the tokenizer.
        2. Load the language model.
        3. Select CPU or GPU automatically.
        4. Generate an answer from a prepared prompt.

    Retrieval and prompt construction are handled by separate
    modules so that the LLM can be changed later without
    redesigning the RAG architecture.
    """

    def __init__(
        self,
        model_name: str = "Qwen/Qwen2.5-1.5B-Instruct",
        max_new_tokens: int = 300,
    ) -> None:

        self.model_name = model_name
        self.max_new_tokens = max_new_tokens

        # --------------------------------------------------
        # Select CPU or GPU automatically
        # --------------------------------------------------

        if torch.cuda.is_available():
            self.device = "cuda"
        else:
            self.device = "cpu"

        print("=" * 70)
        print("INITIALIZING CTI GENERATOR")
        print("=" * 70)

        print(f"\nModel: {self.model_name}")
        print(f"Device: {self.device}")

        # --------------------------------------------------
        # Load tokenizer
        # --------------------------------------------------

        print("\nLoading tokenizer...")

        tokenizer: Any = AutoTokenizer.from_pretrained(
            self.model_name
        )

        self.tokenizer: Any = tokenizer

        print("Tokenizer loaded successfully.")

        # --------------------------------------------------
        # Load language model
        # --------------------------------------------------

        print("\nLoading language model...")

        model: Any = AutoModelForCausalLM.from_pretrained(
            self.model_name
        )

        self.model: Any = model

        # Move model to CPU or GPU
        self.model.to(self.device)

        print("Language model loaded successfully.")

        # Evaluation mode
        self.model.eval()

        print("\nCTI generator initialized successfully.")

    # ------------------------------------------------------
    # Generate answer
    # ------------------------------------------------------

    def generate(
        self,
        prompt: str,
        max_new_tokens: int | None = None,
    ) -> str:

        if not prompt or not prompt.strip():
            raise ValueError("Prompt cannot be empty.")

        generation_limit = (
            max_new_tokens
            if max_new_tokens is not None
            else self.max_new_tokens
        )

        # --------------------------------------------------
        # Tokenize prompt
        # --------------------------------------------------

        inputs = self.tokenizer(
            prompt,
            return_tensors="pt",
            truncation=True,
            max_length=4096,
        )

        # --------------------------------------------------
        # Move tensors to selected device
        # --------------------------------------------------

        inputs = {
            key: value.to(self.device)
            for key, value in inputs.items()
        }

        # --------------------------------------------------
        # Determine padding token safely
        # --------------------------------------------------

        pad_token_id = getattr(
            self.tokenizer,
            "pad_token_id",
            None,
        )

        if pad_token_id is None:
            pad_token_id = getattr(
                self.tokenizer,
                "eos_token_id",
                None,
            )

        # --------------------------------------------------
        # Generate response
        # --------------------------------------------------

        with torch.no_grad():

            output = self.model.generate(
                **inputs,
                max_new_tokens=generation_limit,
                do_sample=True,
                temperature=0.2,
                top_p=0.9,
                pad_token_id=pad_token_id,
            )

        # --------------------------------------------------
        # Remove original prompt tokens
        # --------------------------------------------------

        input_length = inputs["input_ids"].shape[1]

        generated_tokens = output[0][input_length:]

        # --------------------------------------------------
        # Decode generated tokens
        # --------------------------------------------------

        answer = self.tokenizer.decode(
            generated_tokens,
            skip_special_tokens=True,
        )

        return answer.strip()