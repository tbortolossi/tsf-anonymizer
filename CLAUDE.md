# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

**tsf-anonymizer** — a standalone tool (Python package + Docker container +
web UI) that anonymizes PAN-OS tech support files (`.tgz`) and verifies, by an
independent comparison, that the anonymization lost nothing but identifiers.

**Purpose — behaviour stays, identity leaves.** An anonymized TSF is meant to
be analysed *instead of* the original: by TAC, by an external analyst, by an
LLM. Everything that explains *what happened* must survive — sequences,
timings, counters, which rule / zone / gateway / daemon, what was committed
just before — with identifiers replaced *consistently*, so correlation across
files still works. Everything that says *who* must leave: hostnames,
serials, IPs, users, e-mails, object names, and by default the binaries that
embed them. Security work follows the same line: the **method** of an attack
is readable on the copy (a burst of failed logins from one pseudonymised
source, the guessed names, the rhythm, what happened next); the
**attribution** — the real address, account, device — is recoverable only
with the mapping sidecar, which stays with the owner. The compare mode
proves the first half (nothing lost but identifiers); a raw grep of the
device's own identity is the check for the second half, which the compare
cannot do because it only knows the mapping.

It was seeded from TAC-MAN's `libs/anonymizer` and **deliberately duplicated**:
this repo imports nothing from TAC-MAN and must stay that way. Improvements
here are not automatically mirrored there.

## Layout

```
tsf_anonymizer/
  core.py        Anonymizer (pseudonym tables + regexes), XML prescan, file
                 processing, safe extract, metadata-preserving repack
  compare.py     MappingIndex, per-file integrity analysis, archive member
                 check, diff hunks for the UI — NEVER imports the Anonymizer
  jobs.py        JobStore: one directory per job under $TSF_DATA_DIR/jobs,
                 single worker thread, job.json persisted on every transition
  cli.py         tsf-anonymizer anonymize | compare | serve
  web/app.py     FastAPI routes; templates/ + static/ are vanilla HTML/JS
tests/           pytest; test_core.py, test_compare.py, test_web.py
.claude/rules/   invariants, loaded only when a matching file is read:
                 anonymizer-invariants.md (core, compare, mock) and
                 jobs-and-serving.md (jobs, cli, web, Docker) — see below
.claude/skills/read-tsf/  agent skill: SKILL.md is the shell-first method to
                 analyze a TSF (symptom→file→grep map distilled from TAC-MAN's
                 tsf-agent); TSF-GUIDE.md next to it is the human-facing file
                 map — keep the two consistent when either changes.
                 docs/TSF-GUIDE.md is a one-line pointer to the latter (a
                 symlink does not render on github.com).
Dockerfile, docker-compose.yml
```

Also: `mock.py` (the synthetic TSF the docs, screenshots and a first try run
on), `scripts/docs-screenshots.py` (Playwright, drives the real UI on the
mock and writes `docs/screenshots/`), `docs/user-guide.md`,
`docs/architecture.md`, `.github/` (CI, release, CodeQL, templates).

Commands — **uv, never pip/venv/requirements.txt**: `uv sync --all-groups` ·
`uv run pytest` · `uv run ruff check .` · `make check` (lint + tests +
`uv lock --check`, what CI runs) · `make screenshots` · `make docker`
(`docker compose up -d --build`, UI on https://127.0.0.1:8096) · `make help`
for the rest.

## How work happens here

CONTRIBUTING.md is the human-facing version (setup, workflow, releasing); what
follows is only what it does not say or what an agent gets wrong.

- **uv, never pip.** A dependency is added with `uv add` (`--group dev` or
  `--group docs`), which updates `uv.lock`; commit both, `uv lock --check`
  fails CI when they drift. The Dockerfile installs from the lockfile too
  (`uv sync --frozen --no-dev`). Python 3.11 is the floor; CI runs 3.11-3.14.
- **Version in one place.** `pyproject.toml` only, bumped with
  `uv version --bump patch|minor|major` (never by hand); the release steps
  are in CONTRIBUTING.md → *Releasing*. SemVer with the `0.x` reading: minor
  may change what is mapped, patch only fixes.
- **Never commit on `master`.** Branch by intent (`feat/`, `fix/`, `docs/`,
  `chore/`, `refactor/`), Conventional Commits with the reasoning in the
  body, one topic per branch, squash-merge with the PR title as subject. CI
  must be green: `lint`, `test` ×3, `docker` (builds and runs the tool end to
  end), `ui-smoke` (the screenshot script against the real server).
- **Every change to a boundary touches both halves and the rules file.** The
  invariants in `.claude/rules/` are the reason the tool works on real
  archives; a fix in `core.py` without its mirror in `compare.py` shows up as
  an "unexplained" or "leak" line — that is the design, not a nuisance. Add
  the invariant paragraph there, the test, a line under *Unreleased* in
  CHANGELOG.md.
- **Docs follow the code in the same PR.** A flag, an env variable, a default,
  a UI element that changes updates README.md / `docs/user-guide.md`; a UI
  change reruns `make screenshots` and commits the PNGs (they are the smoke
  test's output — a control that moved fails CI before it fails a reader).
- **Clean and rebuild.** `make clean` never touches `data/` or `certs/`;
  `make distclean` also drops `.venv`; `make docker-rebuild` builds with
  `--no-cache` (after a base-image or lockfile change). `pre-commit` (from
  `make setup`) runs ruff, the lockfile check and the 1.5 MB large-file guard
  — a TSF never fits, a screenshot never needs to.
- **An identifier that survives anonymization is a *security* report**
  (SECURITY.md), not an issue. Nothing from a real TSF ever enters an issue,
  a commit, a test or a doc — the mock archive is the reproducer to extend.
  `scripts/check-identifiers.py` (pre-commit, `make lint`, CI) fails on a
  routable IP, an unlisted host/e-mail, a serial shape or a `DOMAIN\user`;
  a synthetic value it does not know goes in `scripts/identifier-allowlist.txt`,
  a real one is replaced and added to the git-ignored `.identifier-denylist`.

## Doctrine — what every invariant follows

- **Two independent halves.** `compare.py` must not call the anonymizer to
  decide whether a change is legitimate; it re-derives expectations from the
  mapping sidecar alone. If it shared code with `core.py`'s replacement logic,
  a bug there would be invisible to the check that exists to catch it.
- **Byte-exact round trip outside identifiers.** Text is decoded with
  `surrogateescape` and written back as bytes; `read_text`/`write_text` are
  banned on payloads (they normalise `\r\n` and replace undecodable bytes).
  Binary files are never rewritten. `.gz` payloads are decided on the
  *decompressed* bytes — compressed bytes always look binary.
- **A replacement never contains a newline**, so line counts are preserved.
  The compare mode treats a line-count change as an error, not a warning.
- **Same original → same pseudonym**, within a run and across runs seeded
  with the same `mapping.json` (`Anonymizer.from_mapping`).

The case law — one invariant per incident a real TSF produced, several
dozen of them, plus the known limitations the tests assert — lives in
`.claude/rules/anonymizer-invariants.md` and `.claude/rules/jobs-and-serving.md`.
They load by themselves when a matching file is read; **read them before
touching `core.py` or `compare.py` for any other reason**, it is where the
bugs live.

## Conventions

- Everything committed is English (code, comments, docs, commits). Talking
  to the user in French is fine.
- No third-party corpus in the repo: `*.tgz`, `*.mapping.json` and `data/`
  are gitignored. Real TSFs are customer material.
- Tests assert on **output**, not on the mapping: "identifier X does not
  survive in the anonymized text" is the property that matters.

## After every TSF analysis: feed the skill

Analyzing a real TSF is the only source of truth about what these archives
actually contain, so **every analysis ends with an update to
`.claude/skills/read-tsf/SKILL.md`** — not optional, not something to ask
about first. The checklist of what to write lives at the end of that file
("Before you finish — feed this file"), where it is loaded exactly when a TSF
is being read; keep it there rather than duplicating it here, and keep
`.claude/skills/read-tsf/TSF-GUIDE.md` in step with it. What the *anonymizer* got wrong on that
TSF belongs in `.claude/rules/anonymizer-invariants.md` instead — an
invariant or a known limitation, plus a test in `tests/`. Genericize
everything: no customer hostname, IP, serial, user or company name enters the
skill, the rules, the docs, or a commit.
