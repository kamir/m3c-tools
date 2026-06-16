"""Local sentence-embedding model wrapper (SPEC-0268).

Defaults to BAAI/bge-m3 (multilingual, dim 1024). The model is downloaded once
to the HuggingFace cache, then runs fully offline. Prefers Apple MPS, then CUDA,
then CPU.

max_seq_length is capped (default 512) because bge-m3's default of 8192 makes
MPS allocate a >60 GiB attention buffer on long inputs ("Invalid buffer size").
Our chunks are ~1500 chars (~400 tokens), so 512 truncates almost nothing and
keeps MPS fast. encode() also falls back to CPU once if the device errors.
"""
from __future__ import annotations

import sys

import numpy as np


class Embedder:
    def __init__(self, model_name, max_seq_length=512, device=None, verbose=True):
        from sentence_transformers import SentenceTransformer
        import torch

        if device is None:
            if torch.backends.mps.is_available():
                device = "mps"
            elif torch.cuda.is_available():
                device = "cuda"
            else:
                device = "cpu"

        self.model_name = model_name
        self._max_seq_length = max_seq_length
        if verbose:
            print(f"[embedder] loading {model_name} on {device} "
                  f"(max_seq_length={max_seq_length}; first run downloads weights)...",
                  file=sys.stderr)
        self.model = SentenceTransformer(model_name, device=device)
        if max_seq_length:
            self.model.max_seq_length = max_seq_length
        self.device = device

    def _to_cpu(self):
        from sentence_transformers import SentenceTransformer
        self.model = SentenceTransformer(self.model_name, device="cpu")
        if self._max_seq_length:
            self.model.max_seq_length = self._max_seq_length
        self.device = "cpu"

    @property
    def dim(self):
        fn = (getattr(self.model, "get_embedding_dimension", None)
              or self.model.get_sentence_embedding_dimension)
        return fn()

    def _encode(self, texts, batch_size, show_progress):
        return self.model.encode(texts, batch_size=batch_size, convert_to_numpy=True,
                                normalize_embeddings=True, show_progress_bar=show_progress)

    def encode(self, texts, batch_size=16, show_progress=True):
        if not texts:
            return np.zeros((0, self.dim), dtype="float32")
        try:
            v = self._encode(texts, batch_size, show_progress)
        except Exception as e:  # noqa: BLE001 - accelerated device can be flaky
            if self.device != "cpu":
                print(f"[embedder] encode failed on {self.device} ({e!r}); retrying on cpu",
                      file=sys.stderr)
                self._to_cpu()
                v = self._encode(texts, batch_size, show_progress)
            else:
                raise
        return np.ascontiguousarray(v, dtype="float32")
