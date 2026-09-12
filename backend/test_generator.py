from app.rag.generator import CTIGenerator


print("=" * 70)
print("CTI GENERATOR TEST")
print("=" * 70)


# ----------------------------------------------------------
# 1. Initialize generator
# ----------------------------------------------------------

print("\n[1] Initializing CTI generator...")

generator = CTIGenerator(
    model_name="Qwen/Qwen2.5-1.5B-Instruct",
    max_new_tokens=150,
)

print("\n[2] Generator ready.")


# ----------------------------------------------------------
# 2. Prepare test prompt
# ----------------------------------------------------------

test_prompt = """
You are a Cyber Threat Intelligence analysis assistant.

Answer the following cybersecurity question clearly,
briefly, and professionally.

Question:
What is ransomware?

Answer:
"""


print("\n[3] Test prompt:")
print(test_prompt)


# ----------------------------------------------------------
# 3. Generate response
# ----------------------------------------------------------

print("\n[4] Generating response...")
print("Please wait. CPU inference may take some time.")


answer = generator.generate(
    prompt=test_prompt,
    max_new_tokens=150,
)


# ----------------------------------------------------------
# 4. Display result
# ----------------------------------------------------------

print("\n")
print("=" * 70)
print("GENERATED ANSWER")
print("=" * 70)

print(answer)


print("\n")
print("=" * 70)
print("CTI GENERATOR TEST COMPLETED")
print("=" * 70)