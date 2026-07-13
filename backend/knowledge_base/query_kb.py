"""
Quick manual test of the retriever, independent of the rest of the app:

    cd backend/knowledge_base
    python query_kb.py
"""
import os
import sys

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from embeddings.local_embeddings import LocalEmbedder
from vector_store.chroma_store import ChromaVectorStore
from retriever.retriever import KnowledgeBaseRetriever
import config

embedder = LocalEmbedder(model_name=config.EMBEDDING_MODEL)
store = ChromaVectorStore(config.PERSIST_DIR, config.COLLECTION_NAME)
retriever = KnowledgeBaseRetriever(embedder, store)

if __name__ == "__main__":
    if store.count() == 0:
        print("Index is empty - run ingest.py first.")
        sys.exit(1)

    query = input("Ask the secure coding KB: ")
    results = retriever.retrieve(query, k=5)

    for r in results:
        print(f"\n[{r['metadata']['source']}]  score={r['relevance_score']}")
        print(r["content"][:300].strip(), "...")
