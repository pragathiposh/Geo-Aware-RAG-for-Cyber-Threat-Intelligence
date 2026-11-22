"""Keep executable legacy demos out of pytest collection.

These files retain their historical ``test_*.py`` names and can still be run
explicitly with ``python test_name.py`` from the backend directory. They do
not define pytest test functions, and several load local models or indexes at
module import time. The automated test suite consists of the files that
actually define pytest tests.
"""

# Load the compiled FAISS extension before other test modules import Torch or
# additional numerical runtimes; on some Windows environments that import
# order otherwise fails during pytest collection. This imports the library
# only: no index files are opened here.
import faiss  # noqa: F401

collect_ignore = [
    "test_automatic_metadata_retrieval.py",
    "test_bm25_retrieval.py",
    "test_embeddings.py",
    "test_filter_builder.py",
    "test_generator.py",
    "test_geo_filter.py",
    "test_geo_hybrid_retrieval.py",
    "test_geo_region.py",
    "test_geo_resolver.py",
    "test_geo_retrieval.py",
    "test_hybrid_retrieval.py",
    "test_lexical_retrieval.py",
    "test_loader.py",
    "test_metadata_aware_retrieval.py",
    "test_metadata_filter.py",
    "test_preprocessing.py",
    "test_prompt.py",
    "test_query_parser.py",
    "test_rag_retriever.py",
    "test_reranker.py",
    "test_retrieval.py",
    "test_retrieval_deduplication.py",
    "test_vector_store.py",
    "test_vector_store_load.py",
]
