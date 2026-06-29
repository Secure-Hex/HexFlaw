# Contributing to HexFlaw

Thanks for contributing. HexFlaw aims for production quality from day one: typed,
tested, and architecturally disciplined. This guide is short on purpose — the rules
below are the ones that actually matter here.

## Development setup

Requires **Python 3.11+**.

```bash
git clone https://github.com/Secure-Hex/HexFlaw.git hexflaw && cd hexflaw
python -m venv .venv && source .venv/bin/activate
pip install -e ".[embeddings,treesitter,pdf,secrets,dev]"
```

## Before opening a PR

All three must pass:

```bash
pytest tests/unit/ -q     # tests
ruff check hexflaw tests  # lint
mypy hexflaw              # types (new/changed code must be clean)
```

- Add or update tests for any non-trivial logic (a branch, a loop, a parser, a
  security path). No new behavior without a runnable check.
- Keep the diff focused. Smallest change that correctly solves the problem.

## Architecture rules (non-negotiable)

The dependency direction is **CLI → Core → Services → Infrastructure**. Violating it
will get a PR rejected.

- The **Core Engine never imports the CLI**. No business logic in `hexflaw/cli/`.
- **Pipeline modules are stateless**: input → output, no global state. Backends
  (embeddings, LLM) are **injected by the orchestrator**, never instantiated inside a
  module.
- **Inter-module contracts are Pydantic models** in `core/models.py`. Don't pass raw
  dicts between modules.
- All **LLM interaction goes through `LLMService`**; never call the provider client
  directly from a module. All **language lookups go through `LanguageService`**;
  never read a language JSON from disk in a pipeline module.

## Security rules (also non-negotiable)

HexFlaw analyzes hostile code. When touching the pipeline:

- **Never execute** the analyzed codebase or a generated PoC.
- Any code sent to the LLM must pass through `LLMService.analyze_code` so it is
  wrapped in `<CODE></CODE>` and **secret-scanned before leaving the machine**.
- Validate every JSON read from disk against its schema; enforce the file
  permissions in the table in `SECURITY.md`.
- Sanitize anything from the analyzed code before it reaches logs or reports.

If your change has a security dimension, say so in the PR description.

## Adding a language

You usually don't need to write code. Language support is a **declarative JSON
definition** (`extensions`, `vuln_profile`, `entry_point_patterns`, `sink_patterns`).

```bash
hexflaw languages add ./my-language.json     # or: install <id> / edit <id>
hexflaw languages validate ./my-language.json
```

Builtin definitions live in `hexflaw/infrastructure/languages/`. Add a matching entry
to `_TS_LANG` in `hexflaw/modules/chunking.py` if a tree-sitter grammar exists.

## Code style

- Type hints on every function and method.
- Google-style docstrings on public classes and functions.
- Explicit error handling — never `except Exception: pass`.
- Match the surrounding code's idiom and comment density.
- Mark deliberate simplifications with a `# ponytail:` comment naming the ceiling and
  the upgrade path, so shortcuts read as intent rather than oversight.

## Commits

Keep commits scoped and messages descriptive. Reference the module (M1, M4, …) or
area when relevant.
