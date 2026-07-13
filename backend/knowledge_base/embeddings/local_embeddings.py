from typing import List

from sentence_transformers import SentenceTransformer


class LocalEmbedder:
    """
    Runs entirely on your machine - no API key, no internet needed after
    the first run (the model downloads once and is cached).

    Uses all-MiniLM-L6-v2: small, fast, and good enough quality for a
    project like this. ~80MB download the first time you run ingest.py.
    """

    def __init__(self, model_name: str = "all-MiniLM-L6-v2"):
        self.model = SentenceTransformer(model_name)

    def embed_documents(self, texts: List[str]) -> List[List[float]]:
        embeddings = self.model.encode(texts, show_progress_bar=False)
        return embeddings.tolist()

    def embed_query(self, text: str) -> List[float]:
        embedding = self.model.encode([text], show_progress_bar=False)
        return embedding[0].tolist()
