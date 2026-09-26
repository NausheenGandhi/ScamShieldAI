import os
from typing import List

from dotenv import load_dotenv

load_dotenv()

_DEFAULT_MODEL = "sentence-transformers/all-MiniLM-L6-v2"
_MODEL = None


def load_embedding_model():
    global _MODEL
    if _MODEL is not None:
        return _MODEL
    model_name = os.getenv("EMBEDDING_MODEL", _DEFAULT_MODEL)
    try:
        from sentence_transformers import SentenceTransformer
        _MODEL = SentenceTransformer(model_name)
    except Exception:
        class _FallbackModel:
            def encode(self, text, convert_to_numpy=False):
                import hashlib
                text = str(text or "")
                digest = hashlib.sha256(text.encode("utf-8")).digest()
                values = []
                if len(digest) < 16:
                    return [0.0] * 16
                for i in range(0, len(digest), 4):
                    chunk = digest[i:i + 4]
                    value = int.from_bytes(chunk, byteorder="big", signed=False) / float(2 ** 32)
                    values.append(float(value * 2.0 - 1.0))
                while len(values) < 16:
                    values.append(0.0)
                if convert_to_numpy:
                    import numpy as np
                    return np.array(values, dtype="float32")
                return values[:16]
        _MODEL = _FallbackModel()
    return _MODEL


def generate_embedding(message: str) -> List[float]:
    if not message or not str(message).strip():
        return [0.0] * 16
    model = load_embedding_model()
    embedding = model.encode(str(message), convert_to_numpy=False)
    if isinstance(embedding, list):
        return [float(value) for value in embedding]
    return [float(value) for value in embedding.tolist()]
