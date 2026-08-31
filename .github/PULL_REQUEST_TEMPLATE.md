## What

<!-- One paragraph: what changes and why it matters. Link the issue: "Closes #12". -->

## Checklist

- [ ] No customer material anywhere in this PR (code, tests, description, commits) — every example is genericized or from `tsf-anonymizer mock-tsf`
- [ ] Tests added or updated, asserting on the **output** (an identifier does not survive), not on the mapping
- [ ] `make check` passes (ruff, pytest, `uv lock --check`)
- [ ] A boundary change touches **both** `core.py` and `compare.py`, and `.claude/rules/anonymizer-invariants.md` gains the invariant
- [ ] Docs updated where a flag, variable or default changed (README, `docs/user-guide.md`; `make screenshots` if the UI changed)
- [ ] `CHANGELOG.md` has a line under *Unreleased*
