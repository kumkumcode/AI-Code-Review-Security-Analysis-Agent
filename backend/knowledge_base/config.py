import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
PERSIST_DIR = os.path.join(BASE_DIR, "vector_store", "chroma_db")

# Chunking
CHUNK_SIZE = 800
CHUNK_OVERLAP = 150

# Local embedding model (sentence-transformers, downloads once, no API key)
EMBEDDING_MODEL = "all-MiniLM-L6-v2"
COLLECTION_NAME = "secure_coding_kb"
