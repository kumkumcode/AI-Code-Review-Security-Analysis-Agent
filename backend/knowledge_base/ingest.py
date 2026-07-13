"""
Run this once (and again whenever data/ changes) to build the vector index:

    cd backend/knowledge_base
    python ingest.py
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from loaders.document_loader import DocumentLoader
from splitter.text_splitter import MarkdownChunker
from embeddings.local_embeddings import LocalEmbedder
from vector_store.chroma_store import ChromaVectorStore
import config


def main():
    print(f"Loading documents from {config.DATA_DIR}")
    loader = DocumentLoader(config.DATA_DIR)
    documents = loader.load()
    print(f"Loaded {len(documents)} documents.")

    if not documents:
        print("No documents found - check that your .md files are under knowledge_base/data/")
        return

    print("Chunking documents...")
    chunker = MarkdownChunker(config.CHUNK_SIZE, config.CHUNK_OVERLAP)
    chunks = chunker.split(documents)
    print(f"Created {len(chunks)} chunks.")

    print("Loading local embedding model (first run downloads it, ~80MB)...")
    embedder = LocalEmbedder(model_name=config.EMBEDDING_MODEL)
    texts = [c["content"] for c in chunks]

    print("Embedding chunks (runs on your machine, no internet needed after download)...")
    embeddings = embedder.embed_documents(texts)

    print("Storing in Chroma...")
    store = ChromaVectorStore(config.PERSIST_DIR, config.COLLECTION_NAME)
    store.add(chunks, embeddings)

    print(f"Done. Collection '{config.COLLECTION_NAME}' now has {store.count()} chunks.")
    print(f"Persisted at: {config.PERSIST_DIR}")


if __name__ == "__main__":
    main()
