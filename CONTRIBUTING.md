# Contributing

Thanks for looking under the hood. This page is the human-facing version of
the working rules; [CLAUDE.md](CLAUDE.md) holds the same rules for the coding
agent, and [.claude/rules/](.claude/rules/) the invariants the real-world runs
taught us — read `anonymizer-invariants.md` before touching `core.py` or
`compare.py`, it is where the bugs live.

## Ground rules

1. **No customer material, ever.** Real tech support files, mappings,
   excerpts, hostnames, IPs, serials, user or company names never enter the
   repository — not in code, tests, docs, commit messages, issues or PR
   descriptions. Genericize: describe the *pattern* (`a 12-digit counter
   right after a dot`), never the value. The synthetic archive from
   `tsf-anonymizer mock-tsf` is the reproducer to extend.
2. **The two halves stay independent.** `compare.py` never imports the
   anonymizer or shares its replacement logic; it re-derives expectations
   from the mapping alone. A bug shared by both sides would be invisible to
   the check that exists to catch it.
3. **Tests assert on output, not on the mapping.** "Identifier X does not
   survive in the anonymized text" is the property that matters; how it was
   mapped is an implementation detail.
4. **Everything committed is English** (code, comments, docs, commits).

## Setting up

The project uses [uv](https://docs.astral.sh/uv/) — one tool for the virtual
environment, the lockfile, running commands and bumping the version. No
`pip`, no `venv`, no `requirements.txt`.

```bash
git clone https://github.com/tbortolossi/tsf-anonymizer.git
cd tsf-anonymizer
make setup                  # uv sync --all-groups, pre-commit hook, Playwright's Chromium
make check                  # lint + tests + lockfile — what CI runs
```

`make setup` is three commands: `uv sync --all-groups` (creates `.venv` from
`uv.lock`, installs the package editable), `uv run pre-commit install` (ruff
and the lockfile check before every commit) and `uv run playwright install
chromium` (only `make screenshots` needs it).

`make` (or `make help`) lists every target. The ones you will use:

| target | what it does |
| --- | --- |
| `make setup` | `.venv` from the lockfile, pre-commit hook, Playwright browser |
| `make test` | `uv run pytest` |
| `make lint` | `uv run ruff check .` |
| `make check` | lint + tests + `uv lock --check` — the CI gate |
| `make mock` | writes a synthetic TSF to try the tool on |
| `make screenshots` | regenerates `docs/screenshots/` from the mock (Playwright) |
| `make docker` | `docker compose up -d --build` |
| `make clean` | removes caches and build output (never `data/`) |

Python 3.11 is the floor (`.python-version`); CI also runs 3.12, 3.13 and 3.14.
`uv python install 3.11` fetches an interpreter if the machine has none.

## Workflow: issue → branch → pull request → squash merge

1. **Open an issue first** for anything that is not a typo — the templates
   ask for what is needed. A *feature request* says what problem it solves
   for whom; a *bug report* comes with a genericized reproducer.
2. **Branch from `master`**, named by intent: `feat/<topic>`, `fix/<topic>`,
   `docs/<topic>`, `chore/<topic>`. One topic per branch; a fix found on the
   way is its own branch.
3. **Commit in [Conventional Commits](https://www.conventionalcommits.org/)
   style** — the history reads that way and the changelog is built from it:
   `feat:`, `fix:`, `docs:`, `test:`, `chore:`, `refactor:`, `perf:`, with a
   scope when it helps (`fix(compare): …`, `docs(read-tsf): …`). The subject
   says *what changed and why it matters*, in one line; the body explains the
   reasoning a reader cannot recover from the diff. A change that breaks the
   CLI, the API or the mapping format carries a `!` (`feat!:`) and a
   `BREAKING CHANGE:` footer.
4. **Open the PR early**, as a draft if it is not ready; the template's
   checklist is the definition of done. CI must be green: lint, tests on
   four Pythons (3.11 to 3.14), the Docker build and the UI smoke test that
   produces the documentation screenshots.
5. **Squash-merge**, with the PR title as the commit subject, then delete
   the branch. `master` is linear and every commit on it is a green,
   self-contained change.

A change that comes out of analyzing a real TSF also updates
`.claude/skills/read-tsf/SKILL.md` (what the archive taught about *reading*
TSFs) and `.claude/rules/anonymizer-invariants.md` (what it taught about
*anonymizing* them), each with a test — see *After every TSF analysis* in
CLAUDE.md.

## Adding a fix for something the anonymizer got wrong

Every real-world defect so far has been the same shape: a boundary the
anonymizer and the compare did not share, or a value discovered on one side
and not the other. So a fix comes in three parts:

1. a test in `tests/` that reproduces the pattern on synthetic data and fails
   before the fix (assert on the output text, per rule 3);
2. the fix, on **both** halves when it is a boundary — every boundary the two
   sides do not share is a future "unexplained" or "leak" report;
3. a one-paragraph invariant in `.claude/rules/anonymizer-invariants.md`
   saying what was wrong, how it was found and what must stay true — future
   readers should never have to rediscover it.

## Documentation

- `README.md` is the front page: what, why, how to run. Keep it current when
  a flag, a variable or a default changes.
- `docs/user-guide.md` walks through the web UI with screenshots generated
  from the mock archive — `make screenshots` regenerates them, commit the
  PNGs with the change that altered the UI.
- `docs/architecture.md` explains the pipeline;
  `.claude/skills/read-tsf/TSF-GUIDE.md` explains tech support files
  themselves (`docs/TSF-GUIDE.md` only points to it — a symlink would not
  render on github.com). `docs/social-preview.png` is the repository's social
  card, uploaded by hand in *Settings → Social preview*.
- `CHANGELOG.md` follows [Keep a Changelog](https://keepachangelog.com/):
  add a line under *Unreleased* in the PR that makes the change.

## Releasing

Versions follow [SemVer](https://semver.org/) with the `0.x` caveat: a minor
bump may change behaviour (a new identifier class, a boundary that moves),
a patch bump fixes without changing what is mapped. The version lives in
`pyproject.toml` only; `uv.lock` and the package read it from there.

```bash
git checkout master && git pull
uv version --bump patch            # or minor / major — edits pyproject.toml + uv.lock
# move the Unreleased entries of CHANGELOG.md under the new version and date
git commit -am "chore: release v$(uv version --short)"
git tag -a "v$(uv version --short)" -m "v$(uv version --short)"
git push origin master --tags
```

Pushing the tag runs the release workflow: it checks the tag matches
`pyproject.toml`, builds the wheel and sdist, publishes a GitHub release with
the changelog section as notes, and pushes the container image to
`ghcr.io/tbortolossi/tsf-anonymizer:<version>` and `:latest`.

## Licence

Contributions are accepted under the project's [Apache-2.0](LICENSE) licence.
By opening a pull request you confirm you have the right to contribute the
code and agree to its distribution under those terms; no separate CLA.
