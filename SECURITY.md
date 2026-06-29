# Security Policy

HexFlaw is a security tool that analyzes potentially **malicious** source code. It
runs with the user's privileges, generates proof-of-concept exploits, and persists
sensitive data. Security is a primary design concern, not an afterthought.

## Reporting a vulnerability

Please report security issues **privately**, not via public GitHub issues.

- **Preferred channel — GitHub Security Advisories (GHSA):** open a private report via
  the repository's **Security → Advisories → "Report a vulnerability"** button
  (`/security/advisories/new`). This keeps the report and discussion private until a
  fix is ready.
- **Alternative:** email **contacto@securehex.cl**.
- Include: affected version/commit, a minimal reproduction, impact, and (if known)
  a suggested fix.
- We aim to acknowledge within **72 hours** and to provide a remediation timeline
  after triage.

Please give us reasonable time to fix the issue before any public disclosure.
Coordinated disclosure is appreciated and credited.

## Scope

The most dangerous attack surface is **the code HexFlaw is asked to analyze**. We are
especially interested in reports that defeat any of the built-in protections:

- **Ingestion (M1):** zip-slip / path traversal, symlink following, git-hook
  execution during clone, billion-laughs / decompression bombs, disguised binaries.
- **Code execution:** any path that causes the analyzed codebase **or** a generated
  PoC to be executed. HexFlaw must *never* execute either.
- **Prompt injection:** code content that escapes the `<CODE></CODE>` delimiters and
  influences the analysis or the generated report/PoC.
- **Secret leakage:** code content (API keys, tokens, private keys) reaching an
  external API or a generated report without redaction.
- **Local privilege / data exposure:** API keys written in plaintext, world-readable
  artifacts, log injection, schema-validation bypass on JSON read from disk.

Out of scope: vulnerabilities that require the user to deliberately disable a
documented protection, or issues in third-party dependencies (report those upstream;
tell us if HexFlaw's usage makes them exploitable).

## Built-in protections (reference)

These are the invariants a report should try to break.

| Area | Protection |
|---|---|
| Analyzed code | **Never executed** (M1/M3/M4) — immovable by design |
| Generated PoC | **Never executed**; non-destructive payloads; destructive-output scanner |
| Archive extraction | Sandbox `700`; zip-slip rejected via `realpath`; symlinks not extracted |
| Git clone | `core.hooksPath=/dev/null`, `GIT_CONFIG_NOSYSTEM`, no prompts, shallow |
| LLM prompts | Code wrapped in `<CODE></CODE>` as data; secret scanning **before** the API call |
| API keys | OS keyring; plaintext `config.json` only as a warned fallback |
| Filesystem | `700` dirs, `600` artifacts, `444` language builtins |
| JSON on disk | Schema validation (`additionalProperties:false`, length limits) |
| Reports | Content escaped; snippets secret-scanned; AI-generated disclaimer |

## Supported versions

HexFlaw is pre-1.0; only the latest release / `main` receives security fixes.
