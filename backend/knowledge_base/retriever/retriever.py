from typing import List, Dict, Optional

from embeddings.local_embeddings import LocalEmbedder
from vector_store.chroma_store import ChromaVectorStore


class KnowledgeBaseRetriever:
    """
    Single entry point the Conversational Code Assistant (and any other
    agent) should call to pull grounding context out of the secure coding
    knowledge base.
    """

    def __init__(self, embedder: LocalEmbedder, store: ChromaVectorStore):
        self.embedder = embedder
        self.store = store

    def retrieve(self, query: str, k: int = 5, category: Optional[str] = None) -> List[Dict]:
        query_embedding = self.embedder.embed_query(query)
        where = {"category": category} if category else None
        results = self.store.query(query_embedding, k=k, where=where)

        formatted = []
        docs = results.get("documents", [[]])[0]
        metas = results.get("metadatas", [[]])[0]
        dists = results.get("distances", [[]])[0]

        for doc, meta, dist in zip(docs, metas, dists):
            formatted.append({
                "content": doc,
                "metadata": meta,
                "relevance_score": round(1 - dist, 4),
            })
        return formatted
