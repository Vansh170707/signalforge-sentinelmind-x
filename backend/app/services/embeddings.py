"""Local text similarity for alert titles.

Default: TF-IDF character n-gram vectors (scikit-learn, zero download, deterministic).
Optional: sentence-transformers (`pip install .[embeddings]`, EMBEDDINGS_BACKEND=sentence-transformers).
Similarity is computed once per unique title, so pair scoring is a dictionary lookup.
"""

from __future__ import annotations

import os

import numpy as np


class TitleSimilarity:
    def __init__(self, titles: list[str]):
        self.index = {t: i for i, t in enumerate(sorted(set(titles)))}
        uniq = list(self.index)
        self.backend = "tfidf-char"
        self.matrix = self._embed(uniq) if uniq else np.zeros((0, 0))
        self.sim = self.matrix @ self.matrix.T if uniq else np.zeros((0, 0))

    def _embed(self, texts: list[str]) -> np.ndarray:
        if os.getenv("EMBEDDINGS_BACKEND") == "sentence-transformers":
            try:
                from sentence_transformers import SentenceTransformer

                model = SentenceTransformer(os.getenv("EMBEDDINGS_MODEL", "all-MiniLM-L6-v2"))
                self.backend = "sentence-transformers"
                return np.asarray(model.encode(texts, normalize_embeddings=True))
            except Exception:  # noqa: BLE001 - fall back to local TF-IDF
                pass
        from sklearn.feature_extraction.text import TfidfVectorizer

        vec = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), lowercase=True)
        m = vec.fit_transform(texts).toarray()
        norms = np.linalg.norm(m, axis=1, keepdims=True)
        norms[norms == 0] = 1
        return m / norms

    def similarity(self, a: str, b: str) -> float:
        if a == b:
            return 1.0
        ia, ib = self.index.get(a), self.index.get(b)
        if ia is None or ib is None:
            return 0.0
        return float(max(0.0, min(1.0, self.sim[ia, ib])))
