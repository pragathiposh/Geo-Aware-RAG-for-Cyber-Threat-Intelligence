from langchain_core.documents import Document


class CTIPromptBuilder:
    """
    Builds prompts for the Cyber Threat Intelligence
    RAG generation pipeline.

    The prompt instructs the language model to:
        - Answer using retrieved CTI evidence.
        - Avoid unsupported claims.
        - Preserve uncertainty.
        - Use cybersecurity metadata when available.
        - Provide a clear and structured response.
    """

    def __init__(self) -> None:

        self.system_instruction = """
You are a Cyber Threat Intelligence analysis assistant.

Your task is to answer cybersecurity questions using
ONLY the retrieved threat intelligence evidence provided
in the context.

Follow these rules:

1. Base your answer primarily on the retrieved evidence.
2. Do not invent malware names, threat actors, countries,
   industries, attack techniques, or other cybersecurity facts.
3. If the retrieved evidence does not contain enough
   information to answer the question, clearly state that
   the available evidence is insufficient.
4. Distinguish between directly reported information and
   reasonable interpretation.
5. When available, mention relevant:
   - Malware families
   - Countries or regions
   - Industries
   - MITRE ATT&CK technique IDs
   - Threat descriptions
6. Do not treat similarity scores as factual evidence.
   They only indicate retrieval relevance.
7. Provide concise but informative cybersecurity analysis.
8. Do not claim that an attack occurred in a country unless
   the retrieved evidence supports that conclusion.
9. Do not confuse a malware family, threat actor, campaign,
   vulnerability, or attack technique.
10. When multiple retrieved sources describe related threats,
    synthesize them carefully without inventing relationships.

Structure the response clearly and professionally.
"""

    def format_context(
        self,
        documents: list[tuple[Document, float]],
    ) -> str:
        """
        Convert retrieved LangChain Documents into
        structured context for the language model.
        """

        if not documents:
            return (
                "No relevant threat intelligence evidence "
                "was retrieved."
            )

        context_parts = []

        for rank, (document, score) in enumerate(
            documents,
            start=1,
        ):

            metadata = document.metadata

            title = metadata.get(
                "title",
                "Unknown",
            )

            countries = metadata.get(
                "countries",
                "Unknown",
            )

            malware = metadata.get(
                "malware_families",
                "Unknown",
            )

            attack_ids = metadata.get(
                "attack_ids",
                "Unknown",
            )

            industries = metadata.get(
                "industries",
                "Unknown",
            )

            context_parts.append(
                f"""
--- Retrieved Source {rank} ---

Title:
{title}

Countries / Regions:
{countries}

Malware Families:
{malware}

MITRE ATT&CK IDs:
{attack_ids}

Industries:
{industries}

Similarity Score:
{score:.4f}

Threat Intelligence Content:
{document.page_content}
"""
            )

        return "\n".join(context_parts)

    def build_prompt(
        self,
        query: str,
        documents: list[tuple[Document, float]],
    ) -> str:
        """
        Build the complete prompt containing:
            - System instructions
            - Retrieved CTI evidence
            - User question
        """

        if not query or not query.strip():
            raise ValueError(
                "Query cannot be empty."
            )

        context = self.format_context(
            documents
        )

        prompt = f"""
{self.system_instruction}

==================================================
RETRIEVED THREAT INTELLIGENCE EVIDENCE
==================================================

{context}

==================================================
USER QUESTION
==================================================

{query.strip()}

==================================================
RESPONSE
==================================================

Provide an evidence-based answer to the user's
question using the retrieved CTI evidence above.
"""

        return prompt.strip()