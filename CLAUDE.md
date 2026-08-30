# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this is

**tsf-anonymizer** — a standalone tool (Python package + Docker container +
web UI) that anonymizes PAN-OS tech support files (`.tgz`) and verifies, by an
independent comparison, that the anonymization lost nothing but identifiers.

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
Dockerfile, docker-compose.yml
```

Commands: `pip install -e ".[dev]"` · `pytest` · `ruff check .` ·
`docker compose up -d --build` (UI on http://127.0.0.1:8096).

## Invariants — what must stay true

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
- **The output archive is the input archive with payloads swapped.**
  `repack_archive` iterates the original `TarInfo` list; it must not re-walk
  the filesystem (`tar.add(dir)`), which loses order and metadata.
- **Serial regex matches 12 or 15 digits only.** 13 digits is an epoch in
  milliseconds; `\d{12,15}` turned every such timestamp into a fake serial.
- **Same original → same pseudonym**, within a run and across runs seeded
  with the same `mapping.json` (`Anonymizer.from_mapping`).
- **Never anonymize** PAN-OS interface names, `BUILTIN_OBJECTS`,
  `VENDOR_DOMAINS`, netmasks, loopback/multicast/link-local. Downstream tools
  match counters and interfaces by name.
- **The web UI has no auth and handles the un-anonymized archive.** Compose
  binds `127.0.0.1` by default; keep that default.
- **The container runs as the host user** (`user:` in compose) so `./data`
  stays deletable without `sudo`.
- **A capped list says it is capped** (`truncated` in diff hunks, `total` in
  the report endpoint, top-50 leaks per file with a total count).

## Known limitations (documented, asserted by tests — do not "fix" silently)

- Hostnames absent from every XML config are not redacted (no reliable
  hostname heuristic without heavy false positives). Test:
  `test_hostname_absent_from_the_config_is_not_redacted`.
- Binary files may embed identifiers; the compare report flags them as
  warnings rather than the anonymizer rewriting them.
- IPv6 untouched; usernames only in known log phrasings.

## Conventions

- Everything committed is English (code, comments, docs, commits). Talking
  to the user in French is fine.
- No third-party corpus in the repo: `*.tgz`, `*.mapping.json` and `data/`
  are gitignored. Real TSFs are customer material.
- Tests assert on **output**, not on the mapping: "identifier X does not
  survive in the anonymized text" is the property that matters.
