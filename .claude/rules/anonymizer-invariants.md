---
paths:
  - "tsf_anonymizer/core.py"
  - "tsf_anonymizer/compare.py"
  - "tsf_anonymizer/mock.py"
  - "tests/test_core.py"
  - "tests/test_compare.py"
  - "tests/test_mock.py"
---

# Anonymizer and compare — invariants

What must stay true in `core.py` and `compare.py`, one entry per incident a
real TSF produced. The doctrine they all follow (two independent halves,
byte-exact round trip, one line stays one line, same original → same
pseudonym) is in CLAUDE.md; this file is the case law. A fix in one half
without its mirror in the other shows up as an "unexplained" or "leak" line
in the compare — that is the design. **A new lesson is added here**, with its
test in `tests/` and a line under *Unreleased* in CHANGELOG.md.

## Invariants

- **Name replacement is one trie-regex pass, never a per-token Python
  callback.** `trie_regex()` builds a longest-match alternation; the previous
  `re.sub(lambda)` over every token ran 11+ minutes on a real 155 MB TSF
  (1.2 GB of text). Boundaries: `(?<![\w.\-])name(?![\w\-])` — a name is
  never replaced inside a word or a hyphenated compound.
- **`extract_archive` returns the archive's original `TarInfo`s and widens
  modes only on the disk copy.** Real TSFs ship files in mode 0000; the
  working copy needs u+rw, the output archive must keep 0000.
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
- **A stray NUL does not make a file binary.** `is_binary_bytes` measured on
  ~700 binary-classified files of eight real TSFs: `slot<n>-console-output.log`
  has one NUL in 4 KB and 200 identifiers; GpTaskStat records have 5 % NUL
  and 16 % control bytes; `wtmp` 90 % NUL; a zip 10 % control. Text with
  NULs is ≤ 2 % NUL, ≤ 5 % other control bytes and ≥ 8 newlines per 4 KB —
  all three, because rewriting a length-prefixed format corrupts it. `.ebl`
  EDL caches are plain IP lists (340 identifiers in one) and left
  `BINARY_EXTENSIONS`. The compare classifies with the same function.
- **The device's own serial can look like a busybox date** (`0101…` =
  MMDDhhmmYYYY) and be refused by the fallback regex — 63 823 raw hits in
  `PA_<serial>_dt_…` telemetry file names on a real PA-7050 whose compare
  reported nothing. `_prescan_system_info` registers it authoritatively, and
  the known-serial trie has no date exclusion.
- **Every mapping entry is a replacement that actually happens.** An entry
  registered whole but whose name embeds an identity an *earlier* pass owns
  can never fire — the earlier pass rewrites that part first. Two real cases:
  `<entry name="acme\jdupont">` (userinfo.xml) is decomposed at prescan into a
  domain and a username (119 299 unexplained lines otherwise), and
  `build_patterns` **hands an object key a FQDN matches inside to the FQDN
  pass** (`fqdn_map[name.lower()]`, pseudonym unchanged), where it is the
  longest alternative and is rewritten whole. Dropping such keys was the
  first answer ('Enloe Domain controllers' after 'Enloe' → host1208), and it
  left the rest of the name in clear: on a real PA-1420 a certificate named
  after its own FQDN with the dots flattened to hyphens
  (`<site>-fw-xx-<domain>-org-au`) came out as `<site>-fw-xx-host014-org-au`
  in 15 files — the site prefix of the device's own hostname, which no
  mapping key covered, so the compare reported nothing. The compare needs no
  mirror: its case-insensitive trie prefers the longest key too, and the
  sidecar carries the object under `fqdns`. Objects embedding an e-mail
  are still dropped (e-mails run even earlier). Same doctrine as the CN
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
  in the member name and in the text. For FQDNs `_` **and `-`** are
  separators (a hostname cannot contain an underscore, PAN-OS glues the name
  with underscores, and a hyphenated compound built on a hostname —
  `adm-<hostname>`, the admin UI's DNS name, 1 379 nginx lines;
  `<hostname>-PBP-ALERTE` — names the same device), in the anonymizer and in
  the compare alike. Objects keep the "never inside a hyphenated compound"
  rule: `web` must not rewrite `web-server-1`. `repack_archive` renames
  members through the same frozen tables — **file name only, never a
  directory** (`mapped_member_name`): directories are PAN-OS layout, and a
  username `cli` once turned `tmp/cli/` into `tmp/user83115/` for 347
  members. The compare pairs files and members by the same mapped name, so
  "output = input with payloads swapped" holds through the mapping, not
  literally.
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
  decides whether such files may ship — `redact_binaries` (on by default in
  the UI and the API, `--redact-binaries` on the CLI) replaces such payloads
  with `REDACTED_PAYLOAD` instead. Measured on eight real TSFs: every redacted
  family has a text twin (`saNN`→`sarNN`, `rule-hit-count.bin`→`-db.txt`,
  `sslvpn-task`→`show_log_globalprotect.txt`) except `wtmp`/`btmp`/`lastlog`
  — admin login history, the one deliberate loss. The core decides with its *own* scanner
  (deliberately duplicated boundaries, not shared code) and the compare
  verifies each redaction was warranted against the original — an
  unwarranted one is a warning, gratuitous data loss.
- IPv6 untouched; usernames only in the log phrasings `_user_re` knows
  (then replaced everywhere).
- Addresses rendered as byte arrays (`[0 0 … 255 255 10 0 0 254]` in Go
  debug output) are not recognised.
