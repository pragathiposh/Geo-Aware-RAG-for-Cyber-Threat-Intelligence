from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from app.rag.pipeline import CTIRAGPipeline


# ----------------------------------------------------------
# FastAPI application
# ----------------------------------------------------------

app = FastAPI(
    title="Geo-Aware RAG Cyber Threat Intelligence API",
    description=(
        "Baseline Retrieval-Augmented Generation API "
        "for Cyber Threat Intelligence."
    ),
    version="0.1.0",
)


# ----------------------------------------------------------
# Initialize RAG pipeline
# ----------------------------------------------------------

print("=" * 70)
print("INITIALIZING CTI API")
print("=" * 70)

pipeline = CTIRAGPipeline(
    vector_store_path="data/vector_store",
    model_name="Qwen/Qwen2.5-1.5B-Instruct",
    top_k=5,
    max_new_tokens=250,
)

print("\nCTI API initialized successfully.")


# ----------------------------------------------------------
# Request model
# ----------------------------------------------------------

class QueryRequest(BaseModel):
    query: str


# ----------------------------------------------------------
# Health endpoint
# ----------------------------------------------------------

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Geo-Aware RAG Cyber Threat Intelligence",
    }


# ----------------------------------------------------------
# Query endpoint
# ----------------------------------------------------------

@app.post("/query")
def query_cti(request: QueryRequest):

    if not request.query.strip():
        raise HTTPException(
            status_code=400,
            detail="Query cannot be empty.",
        )

    try:

        result = pipeline.query(
            user_query=request.query,
        )

        sources = []

        for rank, (document, score) in enumerate(
            result["retrieved_documents"],
            start=1,
        ):

            sources.append(
                {
                    "rank": rank,
                    "title": document.metadata.get(
                        "title",
                        "Unknown",
                    ),
                    "similarity_score": score,
                    "countries": document.metadata.get(
                        "countries",
                        "Unknown",
                    ),
                    "malware_families": document.metadata.get(
                        "malware_families",
                        "Unknown",
                    ),
                    "industries": document.metadata.get(
                        "industries",
                        "Unknown",
                    ),
                    "attack_ids": document.metadata.get(
                        "attack_ids",
                        "Unknown",
                    ),
                }
            )

        return {
            "query": request.query,
            "answer": result["answer"],
            "sources": sources,
        }

    except Exception as error:

        raise HTTPException(
            status_code=500,
            detail=str(error),
        )