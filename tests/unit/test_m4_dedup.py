"""Deduplicación de chunks antes del LLM en M4 (CLAUDE.md §15 T-M4-3, §16)."""

from __future__ import annotations

from hexflaw.core.models import CodeChunk
from hexflaw.modules.m4_static import _dedup_chunks


def _chunk(cid: str, code: str, file: str = "a.py", h: str | None = None) -> CodeChunk:
    return CodeChunk(
        id=cid, file=file, language="python", name=cid, code=code,
        line_start=1, line_end=5, hash=h if h is not None else f"h-{code}",
    )


class _NearDupEmbedding:
    """Embedding de juguete: code igual → vector igual; distinto → ortogonal."""

    def __init__(self) -> None:
        self._vocab: dict[str, int] = {}

    def _vec(self, code: str) -> list[float]:
        key = code.strip()
        idx = self._vocab.setdefault(key, len(self._vocab))
        v = [0.0] * 32
        v[idx % 32] = 1.0
        return v

    def embed(self, text: str) -> list[float]:
        return self._vec(text)

    def embed_batch(self, texts: list[str]) -> list[list[float]]:
        return [self._vec(t) for t in texts]


def test_exact_hash_dedup_no_embedding() -> None:
    chunks = [
        _chunk("a", "system(x)", h="H1"),
        _chunk("b", "system(x)", h="H1"),  # idéntico
        _chunk("c", "other()", h="H2"),
    ]
    out = _dedup_chunks(chunks, None)
    assert [c.id for c in out] == ["a", "c"]


def test_near_dup_cosine_dedup() -> None:
    emb = _NearDupEmbedding()
    chunks = [
        _chunk("a", "system(x)", h="H1"),
        _chunk("b", "system(x)", h="H2"),  # hash distinto pero código igual → near-dup
        _chunk("c", "different()", h="H3"),
    ]
    out = _dedup_chunks(chunks, emb)
    assert [c.id for c in out] == ["a", "c"]


def test_keep_paths_never_dropped() -> None:
    emb = _NearDupEmbedding()
    chunks = [
        _chunk("a", "system(x)", file="lib.py", h="H1"),
        _chunk("b", "system(x)", file="target.py", h="H2"),  # near-dup pero en --path
    ]
    out = _dedup_chunks(chunks, emb, keep_paths=["target.py"])
    assert {c.id for c in out} == {"a", "b"}  # b se conserva por estar en el path


def test_distinct_chunks_all_kept() -> None:
    emb = _NearDupEmbedding()
    chunks = [_chunk("a", "f1()"), _chunk("b", "f2()"), _chunk("c", "f3()")]
    out = _dedup_chunks(chunks, emb)
    assert len(out) == 3
