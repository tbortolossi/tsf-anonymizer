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
.claude/skills/read-tsf/  agent skill: SKILL.md is the shell-first method to
                 analyze a TSF (symptom→file→grep map distilled from TAC-MAN's
                 tsf-agent); TSF-GUIDE.md next to it is the human-facing file
                 map — keep the two consistent when either changes.
                 docs/TSF-GUIDE.md is a symlink to the latter.
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
- **A config that does not parse is still prescanned.** A truncated or
  rejected `failed_candidatecfg.xml` used to register *nothing* — identifiers
  the compare cannot see, since the compare only knows the mapping.
  `_salvage_prescan_xml` pull-parses the parseable prefix with the parent
  context intact, so the vendor-catalog guardrails above still apply; a bare
  regex sweep over `<entry name=…>` would have re-registered the catalog.
- **A fake value is never an input to a later pass.** `Anonymizer._fakes`
  holds every pseudonym handed out; `anon_user`, `anon_ip`, `anon_serial` and
  `register_named_object` return a fake unchanged. Without it, `user 'Zone-A'`
  became `OBJ-0002` then `user001`, and config and logs no longer agreed.
- **Fakes are shaped to not collide with originals**: serials start with 9,
  fake IPs skip any address already seen as an original. When a collision
  still happens (the customer uses 100.64/10), `MappingIndex.collisions`
  reports it as such — separately from leaks, which it would otherwise inflate.
- **Serial fallback: 12 digits not starting `0000`, or `007`+12 — and never
  right after a dot.** Zero-padded counters in `show counter` output are 12
  digits too; 3 434 of them were "anonymized" on the first real run. logdb
  file names are `pan.000100628656.log`: thousands of those sequence numbers
  became fake serials, producing exactly the "changed beyond the mapping"
  warnings the compare exists to raise (its numeric boundary already excluded
  a leading dot; the anonymizer now uses the same one, known serials included).
- **Objects and usernames are one trie — the longest key wins whatever its
  category.** Two tries in sequence let a service named `amanda` (the backup
  software) eat the first label of user `amanda.hudspeth`: `SVC-17959.hudspeth`,
  the surname in clear on a real PA-7000 TSF. `_cs_table` merges both maps
  (objects win a same-key collision, as `MappingIndex` does) behind
  `_obj_re`; `_replace_users` is now only the unfrozen phrasing discovery.
  One regex pass fewer, too — the users pass was the most expensive.
- **An e-mail domain does not start with an all-digit label, and the match
  is not glued to `-word`.** sysd keys read `cfg.net.s6.eth2@252.acl-debug`
  (slot 6, eth2, VLAN 252), and every one became an e-mail — and `252.acl` a
  domain — on a real chassis. The price is a genuine `x@163.com`, absent
  from firewall logs.
- **Every mapping entry is a replacement that actually happens.** An entry
  registered whole but whose name embeds an identity an *earlier* pass owns
  can never fire — the earlier pass rewrites that part first. Two real cases:
  `<entry name="acme\jdupont">` (userinfo.xml) is decomposed at prescan into a
  domain and a username (119 299 unexplained lines otherwise), and
  `build_patterns` drops object keys a FQDN/e-mail matches inside ('Enloe
  Domain controllers' after 'Enloe' → host1208). Same doctrine as the CN
  dedup: one identity, one pseudonym, owned by the pass that wins.
- **Compare never runs difflib on a long line character by character.**
  `_changed_spans` switches to token level past 2 000 chars and gives up
  (one span, unexplained) past 4 000 tokens; XML lines of 24 000 chars exist.
- **Every identity is discovered before anything is rewritten, then the
  tables freeze.** XML prescan (`prescan_tree`) for objects, hosts, serials,
  contacts; then `prescan_text_identities` over every text file for usernames
  (log phrasings), e-mails, `hostname X` phrases — and IPs and
  fallback-shaped serials, so that *nothing* is left to discover at rewrite
  time. Usernames then go through a trie and are replaced everywhere
  (`UID="x"`, `(x)`), not only in the phrasing that revealed them — which is
  also why the frozen rewrite skips the phrasing regex entirely: the trie
  already covers every hit it could find. `anon.frozen = True` turns any
  would-be allocation during the rewrite into an unchanged value plus a
  logged `FileOutcome.warnings` entry — a bug to surface, never silent
  divergence. The `_built_for` recompile is now a safety net for direct
  (unfrozen) API use, not something a TSF run relies on.
- **The device's own name is taken from the device, and member names are
  rewritten too.** `tmp/cli/techsupport_<devicename>_<date>.txt` is named
  after the device (never the model), and `show system info` states the
  hostname, devicename, domain and serial. `_prescan_system_info` registers
  them authoritatively — a name without a digit or hyphen fails the
  `hostname X` heuristic, and went out in clear on three of four real TSFs,
  in the member name and in the text. For FQDNs `_` is a separator (a
  hostname cannot contain one, and PAN-OS glues the name with underscores),
  in the anonymizer and in the compare alike. `repack_archive` renames
  members through the same frozen tables; the compare pairs files and
  members by the *mapped* name, so "output = input with payloads swapped"
  holds through the mapping, not literally.
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
- **Never anonymize** PAN-OS interface names, `BUILTIN_OBJECTS` (`www`
  included — a service named `www` rewrote http://www.w3.org in every vendor
  XML namespace), `VENDOR_DOMAINS`, netmasks, loopback/multicast/link-local,
  or `_USER_STOPWORDS` as usernames — brute-force attempts on an exposed GP
  portal log `failed authentication for user 'error'` (also 'request',
  'block', 'usr'), and pseudonymizing those words rewrote every standalone
  "error" in every log. A word that identifies nobody needs no pseudonym.
  Object and user tries also never match right after `//` (a URL authority)
  and share the glued-timestamp trailing boundary — the compare has both,
  and every boundary the two sides do not share is a future
  unexplained-or-leak report. An `<address>` field holding `10.18.2.254/24`
  is the IP pass's territory (`_IP_LIKE_RE`, not `_IPV4_ONLY_RE`): as a
  "FQDN" it lost its netmask. `MappingIndex.apply` mirrors the anonymizer's
  pass order (fqdns → objects → numeric) because a key can contain another
  category's key — an address object named `FW-Outside-10.30.135.97` is one
  FQDN identity, and applying the IP first destroyed the key (11 000
  "unexplained" lines per config).
- **The web UI handles the un-anonymized archive and the mapping that
  reverses it**, so HTTP Basic auth (`TSF_PASSWORD`) covers *every* route —
  `/api/health` leaks the data dir and job count, `/static` is a mount, not a
  route; no exemption, the container healthcheck authenticates like any other
  client. `create_app(password="")` runs open, for tests and loopback use;
  compose makes the variable mandatory (`${TSF_PASSWORD:?}`) so nothing is
  ever exposed by omission. Compose binds `127.0.0.1` by default; keep that
  default, `TSF_BIND_ADDR` is the deliberate opt-out.
- **TLS fails closed.** `serve` refuses to start when `TSF_TLS_CERT` points
  at a file that is not there, instead of falling back to plain HTTP — a
  silent downgrade of an exposed port is the failure mode worth designing
  against. Serving policy (TLS, credential warnings) lives in `cmd_serve`,
  not in the Dockerfile `CMD`, so a container and a bare
  `tsf-anonymizer serve` behave identically; the container probe is
  `tsf-anonymizer healthcheck`, a normal client that authenticates and
  speaks TLS when the server does. `scripts/make-tls-cert.sh` keeps the CA
  across runs and reissues only the leaf, so an imported trust anchor
  survives a re-issue.
- **The container runs as the host user** (`user:` in compose) so `./data`
  stays deletable without `sudo`.
- **A batch chains, it does not fan out — and it chains by device, not by
  batch.** Several TSFs dropped together are separate jobs; a shared mapping is
  passed by `seed_from`, which the server resolves at submit time to the
  previous job of the same `group` — the firewall the archive comes from
  (`JobStore.latest_in_group`). Two firewalls in one drop are two groups, hence
  two mappings that never link an identifier across devices; the same group
  name a month later continues *that* firewall's mapping instead of starting
  over. The head of a group is its most recently **created** job, not a
  finished one: inside a batch the next upload arrives while the previous
  archive is still queued, and `_seed_ancestor` walks back at run time over a
  job that produced no mapping — a failure in the middle of a batch must cost
  neither the shared pseudonyms of the archives after it nor their run. An
  uploaded seed wins over the chain, and seeds the first archive of *each*
  group. The UI guesses the device from the filename (PAN-OS names a TSF
  `<date>_<time>_techsupport.tgz`, so what a human added around that is the
  device) and the guess is editable: grouping is the user's call, never the
  filename's.
- **Archives run several at a time; a chain still runs in order.** One TSF is
  two long single-core loops (anonymize, then compare) over a few thousand
  files, so one archive used one core and a batch of eight took a working day.
  `JobStore` runs `TSF_WORKERS` archives at once (cpu/4, capped at 4) and
  `_pump` starts a pending job only when `_chain_clear` says nothing it seeds
  from is still queued or running — the *whole* chain, since a parent that
  failed fast may have a grandparent still running. The wait happens in the
  queue, never inside a worker: a chain of jobs each blocking a worker
  deadlocks a full pool. Because the wait is per chain, a batch of unrelated
  firewalls fans out while a batch of one firewall stays a chain. The job
  threads only *orchestrate*: CPU work on threads serialises on the GIL (a
  4-job batch ran on one core, and one job's regex pass starved another's
  extract into looking hung), so every heavy phase runs in worker processes.
- **Heavy passes are spread over processes by detect-then-freeze.**
  `compare_one` is a pure function of the sidecar, so `compare_trees` maps it
  over a `forkserver` pool (`TSF_COMPARE_WORKERS`) and collects reports back
  in path order. The anonymize side earns the same right in two steps
  (`TSF_ANON_WORKERS`): detection (`_detect_in_file`, stateless, parallel)
  reports what each file reveals, the *parent* allocates pseudonyms in path
  order — so counters fall exactly as a sequential run's would — and the
  rewrite then runs with frozen tables, a pure lookup that `anonymize_tree`
  maps over a pool. Allocation during a parallel rewrite would make the
  mapping depend on scheduling and break "same original → same pseudonym";
  freezing is what makes the parallelism sound, and `workers=1` vs `workers=N`
  is asserted byte-identical by test. forkserver, not fork: this runs on a
  worker thread of a live server, and forking a threaded process inherits
  locks held by other threads. One nuance vs the old sequential code:
  detection scans the *original* text, so an IP or serial embedded inside a
  replaced identifier can enter the mapping where the old code never saw it —
  a superset, never a miss.
- **Rewritten `.gz` members are recompressed at level 6, not gzip's default
  9** — measured 12 MB/s at 9 against 38 MB/s at 6 for the same output size,
  the same trade `repack_archive` already makes for the outer archive.
- **Every run keeps its own log.** `_capture_log` tees the package logger into
  `output/job.log` for the duration of one job (they run one at a time, so one
  handler is filtered to that job's own thread, so concurrent jobs do not bleed
  into each other's file), and a crash also stores its traceback in
  `job.error_detail`. The container's stderr is not a log: it is gone the next
  time the container is recreated, and it is the only place that said which
  file and which pattern broke. `core` logs the files it had to skip as
  warnings, and those surface nowhere else — the UI opens the panel by itself
  when a job failed. A failed job also *keeps the phase it died in* so the flow
  marks the step that broke. `Job.phase_durations` records the seconds each
  phase took (also logged at every transition): a slow run says *where* it was
  slow, instead of leaving that to be reconstructed from guesses.
- **A phase that runs for minutes counts.** `extract`, `copy` and `repack` used
  to report `0/1` then `1/1`: on a real TSF the bar sat at 0 % for minutes and
  a slow run could not be told from a hung one. They now report ~100 updates
  whatever the size — `extract` drives `extractall` in slices (which keeps its
  directory-attribute semantics and reads the stream forward-only), `copy`
  counts through `copytree(copy_function=…)`, `repack` through the member loop.
  `Job.updated_at` records when the run last said anything, which is what lets
  the UI say *quiet for 4m* instead of leaving "running" to mean both. The
  jobs list polls every 2 s while anything is queued or running — a batch is
  watched from the list, not from one job's page — and every timer is cleared
  when the view goes away.
- **A capped list says it is capped** (`truncated` in diff hunks, `total` in
  the report endpoint, top-50 leaks per file with a total count).

## Known limitations (documented, asserted by tests — do not "fix" silently)

- Hostnames absent from every XML config, from `show system info` and from a
  `hostname X` log phrase are not redacted (no reliable hostname heuristic
  without heavy false positives). Test:
  `test_hostname_absent_from_the_config_is_not_redacted`.
- Free-text fields (rule descriptions, comments, login banners) are not
  scanned for company names; `<contact>` and `<full-name>` are.
- Binary files may embed identifiers; the compare report flags them as
  warnings rather than the anonymizer rewriting them. The big real-world case
  is `var/log/pan/sslvpn-access/sslvpn-task.log*.gz`: a *binary* serialized
  format (GpTaskStat records, length-prefixed strings) holding SrcIp/UserName/
  Portal per record — ~27 000 flagged identifiers per file on a real TSF.
  Rewriting length-prefixed strings would corrupt the framing; the operator
  decides whether such files may ship — `redact_binaries` (a per-job opt-in:
  UI checkbox, `--redact-binaries`) replaces such payloads with
  `REDACTED_PAYLOAD` instead. The core decides with its *own* scanner
  (deliberately duplicated boundaries, not shared code) and the compare
  verifies each redaction was warranted against the original — an
  unwarranted one is a warning, gratuitous data loss.
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

## After every TSF analysis: feed the skill

Analyzing a real TSF is the only source of truth about what these archives
actually contain, so **every analysis ends with an update to
`.claude/skills/read-tsf/SKILL.md`** — not optional, not something to ask
about first. The checklist of what to write lives at the end of that file
("Before you finish — feed this file"), where it is loaded exactly when a TSF
is being read; keep it there rather than duplicating it here, and keep
`docs/TSF-GUIDE.md` in step with it. What the *anonymizer* got wrong on that
TSF belongs here instead — an invariant or a known limitation above, plus a
test in `tests/`. Genericize everything: no customer hostname, IP, serial,
user or company name enters the skill, the docs, or a commit.
