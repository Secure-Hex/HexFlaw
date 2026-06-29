<!-- Thanks for contributing to HexFlaw. Keep the diff focused. -->

## Summary

<!-- What does this change and why? Reference the module (M0–M6c) or area. -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Refactor / cleanup
- [ ] Docs
- [ ] Language definition (plugin)

## Checklist

- [ ] `pytest tests/unit/ -q` passes
- [ ] `ruff check hexflaw tests` passes
- [ ] `mypy hexflaw` clean for new/changed code
- [ ] Added/updated tests for non-trivial logic
- [ ] Respects the dependency direction (CLI → Core → Services → Infrastructure);
      no business logic in `hexflaw/cli/`, no backend instantiated inside a module
- [ ] Inter-module data uses Pydantic models from `core/models.py`

## Security dimension

- [ ] This change does **not** cause the analyzed code or a generated PoC to execute
- [ ] Any code sent to the LLM still goes through `LLMService.analyze_code`
      (delimited + secret-scanned before leaving the machine)
- [ ] N/A — no security-relevant surface touched

<!-- If a box above is unchecked, explain why here. -->
