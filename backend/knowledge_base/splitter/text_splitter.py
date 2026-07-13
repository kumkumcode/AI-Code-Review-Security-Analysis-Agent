import re
from typing import List, Dict


class MarkdownChunker:
    """
    Splits markdown documents first by headers (so a whole "## SQL Injection"
    section stays together when possible), then further splits any section
    that's still too long, using a character overlap so context isn't lost
    at chunk boundaries.
    """

    def __init__(self, chunk_size: int = 800, chunk_overlap: int = 150):
        self.chunk_size = chunk_size
        self.chunk_overlap = chunk_overlap

    def _split_by_headers(self, text: str) -> List[str]:
        pattern = r"(?=^#{1,6}\s)"
        sections = re.split(pattern, text, flags=re.MULTILINE)
        return [s.strip() for s in sections if s.strip()]

    def _split_long_section(self, text: str) -> List[str]:
        if len(text) <= self.chunk_size:
            return [text]

        chunks = []
        start = 0
        while start < len(text):
            end = start + self.chunk_size
            chunk = text[start:end].strip()
            if chunk:
                chunks.append(chunk)
            start = end - self.chunk_overlap
        return chunks

    def split(self, documents: List[Dict]) -> List[Dict]:
        chunks = []
        for doc in documents:
            sections = self._split_by_headers(doc["content"]) or [doc["content"]]

            chunk_index = 0
            for section in sections:
                for piece in self._split_long_section(section):
                    if len(piece) < 20:
                        continue
                    chunks.append({
                        "id": f"{doc['id']}_chunk{chunk_index}",
                        "content": piece,
                        "metadata": {
                            **doc["metadata"],
                            "chunk_index": chunk_index,
                            "parent_id": doc["id"],
                        },
                    })
                    chunk_index += 1
        return chunks
