# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/) (`0.x`: a minor bump may
change what is mapped, a patch bump only fixes).

## [Unreleased]

### Added
- `scripts/check-identifiers.py`: a guard against real identifiers entering
  the tree (routable IPv4, host names and e-mails outside
  `scripts/identifier-allowlist.txt`, serial shapes, `DOMAIN\user`, a
  private git-ignored denylist, the git author identity), wired as a
  pre-commit hook, into `make lint` and into CI.

### Changed
- `read-tsf` skill and `TSF-GUIDE.md` re-verified against ten real TSFs
  (PA-440 to PA-7080, PAN-OS 10.2.9 to 12.1.4): crash sidecars live in
  `var/cores/crashinfo/` (per DP on a chassis), the PA-3200 family logs its
  dataplane under `opt/dpfs/var/log/pan/`, chassis command dumps repeat every
  DP command per `target-dp` block, `sslvpn-access/` and `frr/` are
  directories, `cp-monitor.log` is per slot on a PA-7000; version-scoped
  files marked (`commit_stats.log`, `show_log_journal.txt`,
  `before|after-sp-imported.xml` are 12.x); `show system resources` removed —
  it is not in the dump on any of them.
- Agent guidance split: `CLAUDE.md` keeps the doctrine and the working rules;
  the per-incident invariants moved to `.claude/rules/` as path-scoped rules
  (`anonymizer-invariants.md` for `core.py`/`compare.py`,
  `jobs-and-serving.md` for jobs, CLI, web and Docker), loaded only when a
  matching file is read. Same content, no invariant dropped.
- Container image on `python:3.14-slim`; Python 3.14 added to the CI matrix
  and the classifiers (3.11 stays the floor).

### Fixed
- The mock's rotated `.gz` members carry a pinned gzip timestamp, so two
  builds of the archive are byte-identical whatever the clock says
  (`test_mock_is_deterministic` was flaky).
- A job's `error` and `error_detail` are set before its status flips to
  `failed`, so a client that sees the verdict always sees the traceback
  (`test_a_failed_job_keeps_a_log_with_the_traceback` was flaky).
- `job.json` is written through a per-writer temp file: the worker and a
  request saving the same job shared one `job.json.tmp`, and the second
  rename failed (`test_a_job_can_be_run_again_from_the_upload_on_disk` was
  flaky).

## [0.3.0] - 2026-08-31

### Added
- `read-tsf` skill: the reading heuristics that lived only in `TSF-GUIDE.md`
  (expired licences, `dagger.log` for what was run and when, the HA peer's
  config in `.ha-remote-rc.xml`, `show_log_globalprotect.txt` columns,
  `content_telemetry.log` as a second `show system info`, two more huge
  files to skip) are now in `SKILL.md` — the method, not only the map.
- `tsf-anonymizer mock-tsf`: a deterministic synthetic TSF (fictional company,
  reserved address ranges) to try the tool on, reproduce bugs and generate the
  documentation — real archives are customer material and never enter the repo.
- `docs/user-guide.md` and `docs/architecture.md`; screenshots of the web UI
  generated automatically from the mock archive (`make screenshots`,
  `scripts/docs-screenshots.py`, Playwright).
- Project files for public release: Apache-2.0 `LICENSE`, `SECURITY.md`,
  `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue and pull request templates,
  `CODEOWNERS`, Dependabot.
- GitHub Actions: lint + tests on Python 3.11/3.12/3.13 + Docker build + UI
  smoke test on every PR; CodeQL; a release workflow on `v*` tags that builds
  the wheel, publishes the GitHub release from this file and pushes the image
  to GHCR.
- `Makefile` with the everyday targets and `.pre-commit-config.yaml`.

### Changed
- Tooling moves to **uv**: `uv.lock`, PEP 735 dependency groups (`dev`, `docs`),
  `.python-version`; the Dockerfile builds from the lockfile in two stages.
- The version lives in `pyproject.toml` only (`uv version --bump …`);
  `tsf_anonymizer.__version__` reads it from the installed metadata.
- Ruff now also enforces import order, modern syntax and bugbear checks.

### Changed
- Binary redaction is **on by default** in the web UI and the API
  (`redact_binaries`): a binary member that embeds mapped identifiers
  (`sslvpn-task` GpTaskStat records, `wtmp`/`btmp`/`lastlog`, `sar` headers,
  `rule-hit-count.bin`) ships as a marker instead. Every family but the login
  history has a text twin that is anonymized normally. The CLI keeps its
  `--redact-binaries` flag.

## [0.2.3] - 2026-08-31

### Fixed
- Member renaming touches file names only, never directories: a username `cli`
  once turned `tmp/cli/` into `tmp/user83115/` for 347 members.

## [0.2.2] - 2026-08-31

### Fixed
- A hyphenated compound built on the device's hostname (`adm-<hostname>`, the
  admin UI's DNS name in nginx logs; `<hostname>-PBP-ALERTE`) names the same
  device and is anonymized as such, in the anonymizer and the compare alike.

## [0.2.1] - 2026-08-31

### Fixed
- The last identifier families the first parallel batch of real TSFs
  surfaced: one trie for objects and usernames (longest key wins whatever the
  category), sysd `interface@vlan` keys are not e-mails, `vsys<n>_` is the one
  underscore that separates an object name, a trailing `$` is the
  machine-account marker rather than part of the username, the device's own
  name wherever PAN-OS puts it.

## [0.2.0] - 2026-08-31

### Added
- Parallel processing: several archives at once (`TSF_WORKERS`), each job's
  heavy passes spread over worker processes (`TSF_ANON_WORKERS`,
  `TSF_COMPARE_WORKERS`) with a detect-then-freeze design that keeps the
  mapping independent of the worker count.
- Batches in the web UI: drag-and-drop several TSFs with one shared mapping,
  one mapping per firewall, or one per archive; a firewall's mapping outlives
  the batch.
- Per-job run log (`output/job.log`) shown in the UI, phase durations, live
  progress for the long phases, *quiet for N min* detection.
- `--redact-binaries`: replace binary payloads that embed identifiers with a
  marker, verified by the compare against the original.
- The `read-tsf` agent skill and `docs/TSF-GUIDE.md`.

### Security
- HTTP Basic auth on every route, fail-closed TLS, loopback bind by default,
  container running as the host user.

## [0.1.0] - 2026-08-30

### Added
- Initial standalone release, seeded from TAC-MAN's anonymizer library:
  anonymize, compare, web UI, Docker image; the first twelve real-TSF
  invariants recorded in CLAUDE.md.

[Unreleased]: https://github.com/tbortolossi/tsf-anonymizer/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/tbortolossi/tsf-anonymizer/compare/v0.2.3...v0.3.0
[0.2.3]: https://github.com/tbortolossi/tsf-anonymizer/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/tbortolossi/tsf-anonymizer/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/tbortolossi/tsf-anonymizer/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/tbortolossi/tsf-anonymizer/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tbortolossi/tsf-anonymizer/releases/tag/v0.1.0
