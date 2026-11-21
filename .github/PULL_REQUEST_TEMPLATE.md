## What and why

## Checklist
- [ ] A failing test came first (or this is docs only), and the suite passes: `uv run pytest -q`
- [ ] `ruff check . --no-cache`, `ruff format --check` and `mypy` are clean
- [ ] No guard was weakened (scope rules, model authority, redaction, file permissions, the audit trail, the no-socket guard), or the PR explains exactly why
- [ ] Anything touching egress, what the tool sends, token handling, evidence privacy or model authority is called out here for an owner decision (see `DECISIONS.md`)
- [ ] A new security property comes with a new mutant in `tools/mutation.py`
- [ ] Synthetic data only; docs say what is implemented and what is not
