from app.embeddings.model import EmbeddingModel


print("======================================")
print("EMBEDDING MODEL TEST")
print("======================================")


model = EmbeddingModel()


text = """
Multi-stage malware execution chain involving
command and control communication, defense evasion,
credential access, and data exfiltration.
"""


print("\nGenerating embedding...")

embedding = model.encode_single(text)


print("\nEmbedding generated successfully.")

print("Embedding dimension:", len(embedding))

print("First 10 values:")
print(embedding[:10])