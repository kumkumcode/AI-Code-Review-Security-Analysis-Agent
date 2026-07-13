import os
from typing import List, Dict


class DocumentLoader:
    """
    Walks knowledge_base/data/ and loads every markdown (.md) file into
    memory, deriving metadata (category, language, source path) from the
    folder structure.

    Expected layout:
        data/
            owasp/A01_2021-Broken_Access_Control.md
            code_smells/...
            best_practices/...
            secure_coding/python/cryptography.md
            secure_coding/java/access_control.md
    """

    def __init__(self, data_dir: str):
        self.data_dir = data_dir

    def load(self) -> List[Dict]:
        documents = []

        if not os.path.isdir(self.data_dir):
            raise FileNotFoundError(f"Data directory not found: {self.data_dir}")

        for root, _, files in os.walk(self.data_dir):
            for filename in files:
                if not filename.lower().endswith(".md"):
                    continue

                filepath = os.path.join(root, filename)
                rel_path = os.path.relpath(filepath, self.data_dir)
                parts = rel_path.split(os.sep)

                category = parts[0] if len(parts) > 1 else "general"
                language = "n/a"
                if category == "secure_coding" and len(parts) > 2:
                    language = parts[1]

                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read().strip()

                if not content:
                    continue

                doc_id = rel_path.replace(os.sep, "_").replace(".md", "")

                documents.append({
                    "id": doc_id,
                    "content": content,
                    "metadata": {
                        "source": rel_path,
                        "category": category,
                        "language": language,
                        "filename": filename,
                    },
                })

        return documents


if __name__ == "__main__":
    # Quick manual check: python loaders/document_loader.py
    import sys
    sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    import config

    loader = DocumentLoader(config.DATA_DIR)
    docs = loader.load()
    print(f"Loaded {len(docs)} documents")
    for d in docs[:3]:
        print(d["id"], "->", d["metadata"])
