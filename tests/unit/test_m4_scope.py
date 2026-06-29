"""Tests del scoping por target en M4 (acota el análisis a la funcionalidad)."""

from __future__ import annotations

from hexflaw.core.models import CodeChunk
from hexflaw.modules.m4_static import _scope_filter
from hexflaw.services.embedding import LocalCPUEmbedding


def _chunk(i: int, code: str) -> CodeChunk:
    return CodeChunk(
        id=f"c{i}",
        file=f"f{i}.go",
        language="go",
        name=f"fn{i}",
        code=code,
        line_start=1,
        line_end=2,
        hash=f"h{i}",
    )


def test_scope_passthrough_when_under_limit() -> None:
    emb = LocalCPUEmbedding(dim=64)
    emb._model = None
    chunks = [_chunk(0, "a"), _chunk(1, "b")]
    assert _scope_filter(chunks, "anything", emb, max_chunks=10) == chunks


def test_path_boost_prioritizes_but_keeps_system_picks() -> None:
    emb = LocalCPUEmbedding(dim=128)
    emb._model = None
    # Chunks irrelevantes al target pero en el path apuntado.
    in_path = [
        CodeChunk(id=f"p{i}", file="modules/git/grep.go", language="go",
                  name=f"g{i}", code="func g(){ unrelated arithmetic }",
                  line_start=1, line_end=2, hash=f"p{i}")
        for i in range(2)
    ]
    # Chunk muy relevante al target pero fuera del path.
    relevant_out = CodeChunk(
        id="r", file="web_src/js/search.ts", language="typescript", name="search",
        code="git grep code search keyword user controlled query",
        line_start=1, line_end=2, hash="r",
    )
    chunks = in_path + [relevant_out]

    kept = _scope_filter(
        chunks, "git grep code search keyword", emb, max_chunks=3,
        boost_paths=["modules/git"],
    )
    # Caben los 3: los del path (boost) + el relevante del sistema (no se pierde).
    assert {c.id for c in kept} == {"p0", "p1", "r"}
    # Con capacidad reducida, el path tiene prioridad sobre el resto.
    kept2 = _scope_filter(
        chunks, "git grep code search keyword", emb, max_chunks=2,
        boost_paths=["modules/git"],
    )
    assert all("modules/git" in c.file for c in kept2)


def test_scope_keeps_most_similar_to_target() -> None:
    emb = LocalCPUEmbedding(dim=128)
    emb._model = None  # fallback determinístico por hashing de tokens
    # Mezcla de chunks: unos sobre "git grep search", otros irrelevantes.
    relevant = [_chunk(i, "func gitGrep(keyword) { runGitGrep search keyword }") for i in range(3)]
    noise = [_chunk(100 + i, "func addNumbers(a, b) { return a plus b }") for i in range(5)]
    chunks = noise + relevant

    kept = _scope_filter(chunks, "git grep code search keyword", emb, max_chunks=3)
    assert len(kept) == 3
    # Los 3 más similares deben ser los de git grep, no el ruido aritmético.
    assert all("gitGrep" in c.code for c in kept)
