# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project
adheres to [Semantic Versioning](https://semver.org/) (`0.x`: a minor bump may
change what is mapped, a patch bump only fixes).

## [Unreleased]

## [0.5.1] - 2026-09-08

### Fixed
- **The free-text pass no longer stalls on the vendor UI catalog.** Real TSFs
  ship `opt/pancfg/mgmt/tmp/ui_content/ui_predefined.js.gz` — 29 MB of
  minified JavaScript whose strings spell `<description>` and close it
  `<\/description>`, so 38 280 tags never close. The lazy
  `<tag>(.*?)</tag>` used to find free-text fields rescanned the whole payload
  for each one: ~30 minutes per pass, matching nothing. Both halves now pair
  the delimiters in a single linear scan — 0.035 s on the same file, with
  output asserted identical to the regex it replaces. On a two-file batch of
  real archives this was 26 minutes of `anonymize` and 50 minutes of `compare`
  per job, entirely wasted.

## [0.5.0] - 2026-09-07

### Added
- **Free text is removed by default.** The content of `<description>`,
  `<comments>`, `<comment>`, `<login-banner>` and the SNMP `<location>` — in
  every config (running, merged, archived, candidate, audit) — and of their
  set-format echo (`description "…"` in a `show config` dump) is replaced by
  `REDACTED-FREE-TEXT`. Measured on real archives: 70–75 % of those fields
  came through every pseudonym pass verbatim (1019/1363, 70/149, 516/587 on
  three trees), carrying exactly the attribution the tool exists to strip —
  people, companies, providers, ticket references — because none of it has a
  shape a pattern can recognise. After the change: 0 fields keep their
  content on the same three trees. One placeholder replaces each *line* of a
  field, so a multi-line description stays as many lines: no replacement ever
  contains a newline. Vendor containers (`<predefined>`, `<threats>`,
  `<application-type>`, the `<global>` catalog a candidate config embeds) are
  skipped — 55 % of all free-text fields on the corpus, prose that explains
  behaviour and names nobody. The set-format side is deliberately
  conservative: a line carrying anything else quoted (a JSON key, an escaped
  quote, a value that runs past the end of the line) is left intact rather
  than half-rewritten. Off with `--keep-free-text` (CLI), by unchecking
  *Remove free text* (UI) or `redact_free_text=false` (API); the choice is
  recorded in the mapping sidecar next to `ip_seed`.
- The compare mirrors it from the sidecar alone, with its **own** copy of the
  rule (never a call into the anonymizer): a removed field is an *explained*
  change, a field that kept its content is a warning
  (`free_text_survivals` in the summary, a KPI in the UI), and a placeholder
  in an archive whose sidecar does not declare the removal is a warning too.
  A line the two halves judge differently is still explained by the plain
  mapping, so a difference of judgement can never turn into unexplained noise.
- The compare's routing-coherence check now also proves coherence *over
  time*: `var/log/pan/routed.log*` (add/delete route events, plain or
  `.gz`-rotated), and the `show routing protocol bgp loc-rib` / `rib-out` and
  `ospf dumplsdb` (LSDB) CLI sections, feed the same route/nexthop/containment
  relations the static config and RIB snapshot already checked. Same
  conservative rule as the rest of the check: a line whose prefix or nexthop
  does not parse cleanly is skipped silently, never guessed at. No mapping,
  no anonymizer import — same code re-derives both trees independently.

### Changed
- Public IPv4 pseudonyms now come from the same keyed-PRF prefix tree as
  private ones: one catch-all tree over 240.0.0.0/4, with the real top
  nibble folded into the PRF path seed and every bit down to the host octet
  tree-flipped. Two real addresses sharing a k-bit prefix (k ≥ 4) share the
  fake prefix to depth k, so public routing relations survive on the copy —
  the default route's nexthop stays inside its connected WAN /30, BGP/OSPF
  aggregates still contain their members (120 of 246 containment relations
  were lost on one real box under the previous per-/24 grouping), and
  prefixes announced mid-log stay coherent; masks never change. The
  compare's `public_divergences` count is now expected ≈ 0 (measured
  0 / 0 / 0 on three real trees that showed 101 / 5 / 0 before); it stays a
  counted number, never a hard error. The anti-reuse probe no longer hands
  out `.0`/`.255` host octets. Minor-worthy: this changes what public
  pseudonyms look like, not what is mapped — a mapping sidecar written by
  the old scheme keeps its explicit pairs verbatim when seeding a new run
  (`Anonymizer.from_mapping`), only *new* allocations use the tree, and
  `ip_seed` rides the sidecar unchanged.

### Fixed
- Routing-protocol names (`bgp`, `ospf`, `ospfv3`, `rip`, `bfd`, `pim`,
  `igmp`, `msdp`, `vrrp`) joined `BUILTIN_OBJECTS` and are never identities:
  a real box with a service object named `bgp` had every
  `> show advanced-routing bgp loc-rib-detail` command echo rewritten to
  `… SVC-0368 loc-rib-detail`, which lost the BGP sections to any reader of
  the copy — caught by the routing-coherence check's dynamic view as 29
  missing routes on the anonymized side. Such a bare name now stays in
  clear when a customer genuinely uses it (it identifies nobody — the same
  trade `www`, `lan` and the English stopwords already make); compounds
  like `bgp-peering-lyon` are still mapped.

## [0.4.0] - 2026-09-06

### Changed
- The compare's scan — every mapping key over every payload, which is both
  how a line is explained and how a leak is found — now runs as an
  Aho-Corasick automaton (new dependency: `pyahocorasick`) instead of three
  compiled trie regexes. The automaton reports *candidates* and each one is
  revalidated against the very same boundary assertions the regexes spliced
  inline, so the semantics are unchanged: longest key first at a position
  (backtracking to a shorter key whose boundary holds), pass order FQDNs →
  objects → numeric, the lowered-copy scan for case-insensitive keys with the
  `re.IGNORECASE` fallback where that copy cannot serve. Measured on a real
  38 MB log, the three passes cost 1.0 s against 4.1 s, and building the
  index over 26 828 keys 0.04 s against 0.40 s — paid once per worker
  process; end to end, the compare of a real tree went from 145 s to 61 s
  and of another from 131 s to 55 s (single worker). The trie regexes stay
  the reference implementation and the fallback wherever the C extension
  cannot be installed (`compare.USE_AHOCORASICK`); a test forces both paths
  and asserts they produce byte-identical `apply` output, identical
  `find_leaks` findings and an identical `CompareReport` on the mock
  archive, and the same was verified on three real archives (both trees
  each, 1.6 GB of text on one of them): zero divergence.
- The XML prescan runs on the same process pool as the rest of the job
  (`TSF_ANON_WORKERS`, `--workers`), and each XML is parsed once. A worker
  parses one config and *reports* the identities it holds — it is handed no
  `Anonymizer` and allocates nothing; the parent registers those findings in
  path order, in the document order each file yielded them, so the mapping is
  the sequential one whatever the worker count. Measured on 37 MB of
  synthetic configs: 1.51 s to 0.57 s at four workers, mapping byte-identical
  at 1, 4 and 8. The compare's XML structure check no longer builds a DOM to
  read a tag sequence either — 0.83 s and +276 MB down to 0.39 s and +13 MB
  per 22 MB pair, with the same verdict on every shape (namespaces, comments,
  processing instructions, entities, encoding declarations, unparseable
  documents).
- `tsf-anonymizer serve` binds `127.0.0.1` by default instead of `0.0.0.0`
  (minor: changes what a bare `serve` is reachable from). A tool that
  handles un-anonymized archives and the mapping that reverses them should
  not be reachable off the box until an operator asks for it with
  `--host`; the compose default already published the container on
  loopback (`TSF_BIND_ADDR`), so this closes the gap for anyone running the
  CLI directly. The Dockerfile's `CMD` already passed `--host 0.0.0.0`
  explicitly (the container binds every interface inside its own network
  namespace; it is the host-side port publish that stays loopback-only via
  compose), so the container's behaviour is unchanged.
- Passes that cannot match are no longer run. The username, e-mail and
  hostname patterns are preceded by a check for the literal every one of
  their matches contains, and the frozen rewrite skips the serial *fallback*
  regex, whose work the text prescan has already done (the known-serial trie
  still runs, and an unfrozen anonymizer still discovers serials with it).
  Measured on a real archive: the literal is absent from 72 % of the text for
  `hostname`, 50 % for `@` and 38 % for `user`, and the serial fallback cost
  1 212 ms per 31 MB of log for nothing. Output unchanged — byte-identical
  anonymized trees on the real corpus, and identical detection findings file
  by file.
- The case-insensitive tries (FQDNs and e-mail domains in the anonymizer, the
  same keys in the compare's `apply` and leak scan) now match a lowered copy
  of the text with a trie compiled without `re.IGNORECASE`, and cut the
  output from the original text at those offsets. Measured on a real 31 MB
  log: the FQDN pass 2 096 ms to 1 262 ms, the compare's `apply` 6 440 ms to
  3 540 ms. Output is unchanged — byte-identical anonymized trees and
  identical integrity reports on eight real archives — and text holding one
  of the three codepoints where `lower()` and `re.IGNORECASE` disagree keeps
  the flag.
- Worker processes are now sized when each heavy phase starts, not once at
  startup. `TSF_ANON_WORKERS` / `TSF_COMPARE_WORKERS` are floors describing a
  machine whose every archive slot is busy; a phase that runs while fewer
  archives can — a lone upload, or a batch of one firewall, which is a chain
  and runs one archive at a time — takes the idle share of the cores instead,
  up to the core count. Setting either variable pins the count as before. The
  job log records what each phase settled on.
- IP pseudonyms now preserve prefix structure (minor: changes what fakes
  look like). Private addresses stay inside their own RFC 1918/CGNAT class
  with the host octet kept (`10.1.2.3` → `10.x.y.3`), driven by a keyed PRF
  prefix tree whose key travels in the mapping sidecar as `ip_seed`; every
  other address maps into 240.0.0.0/4 (class E), one fake /24 per real /24.
  Same real prefix → same fake prefix: subnets, static and dynamically
  learned route destinations, LSDB entries and nexthops stay mutually
  coherent — across files and across TSFs seeded from the same mapping. An
  address can no longer map to itself; a structural fake that would repeat
  a used value probes within its /24. The compare now **applies** mapping
  keys that collide with pseudonym values instead of dropping them (they
  are still excluded from the leak scan and reported as collisions).
- Archive extract and repack are now isal-backed when the `isal` package
  (PyPI project `python-isal`) has a wheel for the platform, falling back to
  stdlib `gzip`/`zlib` otherwise. Measured on a real 565 MB TSF, single core:
  extract 92s → ~35s, repack 66s → ~25s. isal's encoder only offers levels
  0-3 (not zlib's 0-9); level 3, its slowest/best-ratio setting, is used
  throughout, because even at level 3 isal still outruns stdlib zlib at
  level 6 (the level this module already uses over the default 9) by 2-3x on
  this kind of text — there is no speed left to buy by dropping a level, so
  the ratio isn't traded away as it is for zlib's 9 → 6. The trade that *is*
  made: isal's output runs somewhat larger than zlib's for the same content
  (~15-20% measured on synthetic archives) — the outer `.tgz` and any
  rewritten `.gz` member compress worse, never differently once decompressed.
  isal's `GzipFile` cannot be trusted with the backward seek `extract_archive`
  performs (`getmembers()` scans forward to the end, then `extractall()`
  restarts near the beginning) — confirmed misdecoding after such a rewind
  on isal 1.8.0 — so reading only ever drives it forward: the compressed
  archive is decompressed in one sequential pass to a plain temp `.tar` on
  the same volume, and ordinary (fast, unaffected) random-access tarfile
  reading happens against that. Writing has no such restriction (`tarfile`
  never seeks backward while it writes), so the repack path wraps isal's
  `GzipFile` directly as `tarfile`'s own `fileobj`, exactly as `tarfile`
  itself wraps stdlib's `GzipFile` for `mode="w:gz"`. Decompressed bytes are
  asserted identical to the stdlib path on the synthetic mock archive,
  outer and inner `.gz` alike.

### Fixed
- A non-UTF-8 byte in an XML payload no longer fails the whole file's
  comparison report. Text is decoded with `errors="surrogateescape"`, so such
  a byte survives as a lone surrogate; both `expat.Parser.Parse` and
  `ET.fromstring` re-encode a `str` argument to UTF-8 before parsing, which
  raises `UnicodeEncodeError` for a surrogate rather than the parser's own
  error — uncaught, it escaped `_xml_structure` and turned the file's report
  into a bare "comparison failed" instead of the graceful `xml_structure =
  "unparseable"` verdict a truncated or otherwise broken document already
  gets. `_xml_structure` now catches `UnicodeEncodeError` alongside
  `expat.ExpatError`.
- A bare common English word is no longer an identity, in any category:
  brute-force login guesses (`failed authentication for user 'install'`,
  `'up'`, `'inventory'`) and config entries genuinely named `data` or
  `bytes` were pseudonymized and then replaced corpus-wide, destroying
  command echoes (`> show chassis inventory`), status vocabulary
  (`Connection status: up`), fixed counter text (`size (bytes)`,
  `Resource monitoring sampling data`) and the `install` verb of
  `opt/panrepo/logs/history.log` and of audit.log on real archives. A new
  `_ENGLISH_STOPWORDS` guard sits on the two allocation choke points
  (`anon_user`, `register_named_object`). Trade-off, documented in the
  invariants: an account or object named *exactly* a bare English word stays
  in clear — it identifies nobody, and any spelling with a digit, dot or
  hyphen (`jmartin`, `data-01`) is unaffected.
- PAN-OS interface names are preserved on the FQDN route too: `vlan.800` /
  `tunnel.2` are FQDN-shaped, and a subinterface entry name registered
  through the FQDN branch rewrote every zone `<member>` holding it into
  `hostNNN.anon.internal` on a real TSF. `anon_fqdn` now refuses interface
  names, as `register_named_object` always did.
- An original address equal to an already-handed-out pseudonym is now
  mapped instead of skipped. With same-class fakes the old skip left a real
  private address in clear and outside the mapping — invisible to the leak
  scan, caught on a real TSF by the new routing-coherence check. The
  compare reports the string ambiguity as a *collision*, as before.
- The routing-coherence check scopes its verdict to the private relations
  prefix preservation guarantees; divergences that involve public space
  (aggregation beyond the per-/24 grouping) are counted and shown, not
  errors. It prefers `.merged-running-config.xml` (Panorama-managed boxes
  ship an empty `<interface>` section in `running-config.xml`), takes
  connected networks from the RIB's C-flagged rows too, and compares
  containment as ancestor sets instead of O(n²) pairs (6 903-row real RIB).
- The fake-IP generators are injective again: the private one merged `.0`/`.1`
  host octets every 256th allocation and the public one cycled over the 762
  RFC 5737 addresses — on one real archive 54 197 of 84 971 distinct IPs
  (public attack sources included) silently shared a pseudonym, breaking
  correlation on the copy. Public pseudonyms now spill into 240.0.0.0/4
  (class E — never routable, never a real third party) once RFC 5737 is
  exhausted, the generation loop skips every pseudonym already handed out,
  and the compare reports a non-injective mapping (*duplicate pseudonyms*)
  in its summary and the UI.
- An object whose name embeds a FQDN is now rewritten whole by the FQDN pass
  instead of having its key dropped: a certificate named after its flattened
  FQDN (`<site>-fw-xx-<domain>-org-au`) kept the site prefix of the device's
  hostname in clear in 15 files of a real PA-1420 TSF. The key moves to the
  `fqdns` table of the sidecar with the pseudonym it already had; the compare
  explains it unchanged.

### Added
- The compare now checks **routing coherence** structurally: the config and
  both RIB formats are re-parsed on each side, and every structural
  relation (a nexthop inside a connected subnet, a route containing another
  route or a connected network, every prefix length) must hold on the
  anonymized tree iff it holds on the original — summary key `routing`,
  one line in the CLI compare output, a KPI tile in the UI. This is the
  check that fails if prefix preservation ever regresses; per-line
  explanation cannot see it.
- The mock TSF now exercises routing coherence: a `<virtual-router>` and a
  `<logical-router>` with static routes, a RIB in both formats (classic
  `show routing route` with learned OSPF/BGP rows and ages,
  `show advanced-routing route`), an OSPF LSDB extract, and a dated
  `routed.log` flap of the learned route — the fixtures the
  prefix-preservation tests assert on.
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

[Unreleased]: https://github.com/tbortolossi/tsf-anonymizer/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/tbortolossi/tsf-anonymizer/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/tbortolossi/tsf-anonymizer/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/tbortolossi/tsf-anonymizer/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/tbortolossi/tsf-anonymizer/compare/v0.2.3...v0.3.0
[0.2.3]: https://github.com/tbortolossi/tsf-anonymizer/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/tbortolossi/tsf-anonymizer/compare/v0.2.1...v0.2.2
[0.2.1]: https://github.com/tbortolossi/tsf-anonymizer/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/tbortolossi/tsf-anonymizer/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/tbortolossi/tsf-anonymizer/releases/tag/v0.1.0
