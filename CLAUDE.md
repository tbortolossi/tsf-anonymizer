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
docs/TSF-GUIDE.md  what a TSF contains and how to read one (user-facing)
.claude/skills/read-tsf/  agent skill: shell-first method to analyze a TSF
                 (symptom→file→grep map distilled from TAC-MAN's tsf-agent);
                 keep it consistent with TSF-GUIDE.md when either changes
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
- **Name replacement is one trie-regex pass, never a per-token Python
  callback.** `trie_regex()` builds a longest-match alternation; the previous
  `re.sub(lambda)` over every token ran 11+ minutes on a real 155 MB TSF
  (1.2 GB of text). Boundaries: `(?<![\w.\-])name(?![\w\-])` — a name is
  never replaced inside a word or a hyphenated compound.
- **`extract_archive` returns the archive's original `TarInfo`s and widens
  modes only on the disk copy.** Real TSFs ship files in mode 0000; the
  working copy needs u+rw, the output archive must keep 0000.
- **`delete_original` deletes only after a clean integrity report.** Errors
  or archive mismatches keep the original with `original_kept_reason` set;
  a human deletes it via `POST /api/jobs/{id}/delete-original`.
- **The prescan reads customer configuration, not vendor content.**
  `_SKIP_SUBTREES` (`<predefined>`, `<threats>`…) and `_is_prescan_candidate`
  (global.xml, predefined.xml, updates/, regip/, report templates) exist
  because a candidate config embeds the App-ID catalog: 41 973 names like
  `Apple`, `bgp`, `enabled` were registered as objects and then rewritten
  inside XML tags. The boundaries `(?<![\w.\-<\/])…(?![\w\-=])` are the
  second line of defence: never match right after `<` / `</`, never before `=`.
- **A fake value is never an input to a later pass.** `Anonymizer._fakes`
  holds every pseudonym handed out; `anon_user`, `anon_ip`, `anon_serial` and
  `register_named_object` return a fake unchanged. Without it, `user 'Zone-A'`
  became `OBJ-0002` then `user001`, and config and logs no longer agreed.
- **Fakes are shaped to not collide with originals**: serials start with 9,
  fake IPs skip any address already seen as an original. When a collision
  still happens (the customer uses 100.64/10), `MappingIndex.collisions`
  reports it as such — separately from leaks, which it would otherwise inflate.
- **Serial fallback: 12 digits not starting `0000`, or `007`+12.** Zero-padded
  counters in `show counter` output are 12 digits too; 3 434 of them were
  "anonymized" on the first real run.
- **Compare never runs difflib on a long line character by character.**
  `_changed_spans` switches to token level past 2 000 chars and gives up
  (one span, unexplained) past 4 000 tokens; XML lines of 24 000 chars exist.
- **Identities are discovered before anything is rewritten, in two passes.**
  XML prescan (`prescan_tree`) for objects, hosts, serials, contacts; then
  `prescan_text_identities` over every text file for usernames (log
  phrasings), e-mails and `hostname X` phrases. Usernames then go through a
  trie and are replaced everywhere (`UID="x"`, `(x)`), not only in the
  phrasing that revealed them. Tables that still grow mid-run (an e-mail
  domain in file 3) trigger a recompile at the next file — `_built_for`.
- **A FQDN registers its parent domains** down to the registrable one, and
  the FQDN regex allows a dot before: `https://apex/` and `*.apex` survived a
  raw grep of the anonymized real TSF while the compare reported 0 leaks,
  because the apex was never a mapping key. **The compare only knows the
  mapping** — a raw grep for the customer's name is the check it cannot do.
- **Under an identity container, any spelling is an identity.**
  `_IDENTITY_PARENTS` (users, admin, zone, address, certificate, server…)
  bypasses the lowercase-word vocabulary heuristic, which had swallowed a
  real admin named `jmartin`. An entry named by its IP is owned by the IP
  pass; one named by a FQDN by the FQDN pass — never also an `OBJ-…`.
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
- Free-text fields (rule descriptions, comments, login banners) are not
  scanned for company names; `<contact>` and `<full-name>` are.
- Binary files may embed identifiers; the compare report flags them as
  warnings rather than the anonymizer rewriting them.
- IPv6 untouched; usernames only in the log phrasings `_user_re` knows
  (then replaced everywhere).
- Addresses rendered as byte arrays (`[0 0 … 255 255 10 0 0 254]` in Go
  debug output) are not recognised.

## Conventions

- Everything committed is English (code, comments, docs, commits). Talking
  to the user in French is fine.
- No third-party corpus in the repo: `*.tgz`, `*.mapping.json` and `data/`
  are gitignored. Real TSFs are customer material.
- Tests assert on **output**, not on the mapping: "identifier X does not
  survive in the anonymized text" is the property that matters.
