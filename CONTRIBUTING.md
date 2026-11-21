# Contributing

Thanks for looking. This is a security tool, so the bar for changes is deliberately high, and it is early: today it checks scopes
and keeps an evidence database; the collectors are not built yet (see the README).

## Set up (about two minutes)

```bash
git clone https://github.com/MDPorsch/scoped-evidence-agent && cd scoped-evidence-agent
uv sync                                  # Python 3.13 and the locked dependency set
uv run pytest -q                         # unit, integration, negative, adversarial and property tests
uv run ruff check . --no-cache && uv run ruff format --check . && uv run mypy
```

`--no-cache` matters: ruff's cache can hide an import-order error that CI will find.

## Rules that are not negotiable

1. **Tests first.** A change in behaviour starts with a failing test, and a security claim needs a test that would fail if the
   claim were false. Never skip or xfail a test to make a build green.
2. **Do not weaken a guard** (the scope rules, the model's lack of authority, redaction, file permissions, the append-only audit
   trail, the no-socket test guard) to make something easier. If you think one is wrong, open an issue first.
3. **Anything that changes egress, what the tool sends, token handling, evidence privacy or what a model may do needs the owner's
   decision.** Say so in the pull request. `docs/` and `LIMITATIONS.md` record what the project does and does not do; a change that
   contradicts them needs a decision, not just a patch.
4. **No exploitation.** The tool does not produce exploit code, attack payloads or attack chains (D-E59), and a model is never an
   authority over targets, scope or finding truth.
5. **Synthetic data only.** No real credentials, tokens, keys, names, addresses or client data in code, tests, fixtures, issues or
   pull requests. Fixtures use reserved names (`.invalid`) and documentation addresses.
6. **Be honest in docs.** Separate implemented from planned, and say what a result does not show.

## Mutation check (optional, slow)

`uv run python tools/mutation.py` injects known bugs into a scratch copy and requires the suite to catch every one. If you change code
a mutant patches, "pattern not found" means the mutant is stale and must be updated, not ignored. A new security property should come
with a new mutant.

## Security problems

Please do not open a public issue with exploit detail. Follow `SECURITY.md`.

By contributing you agree your contribution is licensed under the Apache License 2.0.
