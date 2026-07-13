from typing import List, Dict, Optional

import chromadb


class ChromaVectorStore:
    """
    Persistent local Chroma collection. Data is written to disk under
    vector_store/chroma_db/ so it survives restarts - you only need to
    re-run ingest.py when the source docs change.
    """

    def __init__(self, persist_dir: str, collection_name: str = "secure_coding_kb"):
        self.client = chromadb.PersistentClient(path=persist_dir)
        self.collection = self.client.get_or_create_collection(name=collection_name)

    def add(self, chunks: List[Dict], embeddings: List[List[float]]):
        self.collection.add(
            ids=[c["id"] for c in chunks],
            documents=[c["content"] for c in chunks],
            embeddings=embeddings,
            metadatas=[c["metadata"] for c in chunks],
        )

    def query(self, query_embedding: List[float], k: int = 5, where: Optional[dict] = None):
        return self.collection.query(
            query_embeddings=[query_embedding],
            n_results=k,
            where=where,
        )

    def count(self) -> int:
        return self.collection.count()

    def reset(self):
        name = self.collection.name
        self.client.delete_collection(name)
        self.collection = self.client.get_or_create_collection(name=name)
