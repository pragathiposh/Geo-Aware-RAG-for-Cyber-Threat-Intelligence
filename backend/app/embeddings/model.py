from sentence_transformers import SentenceTransformer


MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"


class EmbeddingModel:
    """
    Wrapper around the Sentence Transformer embedding model.
    """

    def __init__(self, model_name: str = MODEL_NAME):
        self.model_name = model_name

        print(f"Loading embedding model: {model_name}")

        self.model = SentenceTransformer(model_name)

        print("Embedding model loaded successfully.")

    def encode(
        self,
        texts: list[str],
    ) -> list[list[float]]:
        """
        Convert a list of texts into embedding vectors.
        """

        embeddings = self.model.encode(
            texts,
            convert_to_numpy=True,
            show_progress_bar=True,
        )

        return embeddings.tolist()

    def encode_single(self, text: str) -> list[float]:
        """
        Convert a single text into an embedding vector.
        """

        embedding = self.model.encode(
            text,
            convert_to_numpy=True,
        )

        return embedding.tolist()