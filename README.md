# TSF Anonymizer

Anonymize PAN-OS tech support files (TSF) before sharing them, **without losing
what makes them useful for troubleshooting** — and prove it with a compare mode.

Standalone: one Python package, one container, no external service. Derived
from the anonymizer lib in TAC-MAN, duplicated on purpose so this project has no
dependency on that repository.

## What it does

**Anonymize** — extracts the `.tgz`, pre-scans every XML config for named
objects (addresses, zones, rules, gateways, users, …), hostnames, LDAP domains,
certificate subjects, e-mail recipients and serials, then rewrites every text
file (rotated `.gz` logs included) with consistent pseudonyms:

| class | original | replacement |
|---|---|---|
| private IPv4 | `10.1.2.3` | `100.64.x.y` (RFC 6598, never a real internal range) |
| public IPv4 | `8.8.8.8` | `192.0.2.x` / `198.51.100.x` / `203.0.113.x` (RFC 5737) |
| FQDN / hostname | `fw01.acme.local` | `host007.anon.internal` |
| e-mail | `j.dupont@acme.fr` | `user003@host002.anon.internal` |
| named object | `Zone-Prod-DMZ` | `ZONE-0012` (category prefix kept) |
| username | `jdupont` | `user001` |
| serial | `001901000123` | `900000000001` (same length, leading 9) |

Same original value → same pseudonym everywhere, so VPN peers, LDAP servers,
rules and users can still be correlated across logs and config.

What is **not** touched: PAN-OS interface names (`ethernet1/1`, `ae1`, `tunnel.1`),
built-in objects (`any`, `trust`, `vsys1`, `admin`…), vendor domains
(`*.paloaltonetworks.com`), netmasks, loopback/multicast/link-local addresses,
timestamps, counters, and every binary file (copied through byte for byte).

The output archive keeps the input's member order and metadata; only payloads
change. A `<name>.mapping.json` sidecar records every substitution — **it is the
key to the customer's identity: keep it with the customer, never with the
anonymized TSF.**

**Compare** — reads the original and the anonymized archive back and checks,
independently of the anonymizer:

1. every changed line is explained by the mapping (token-level re-application,
   then span-level inspection; what remains is *unexplained* and shown for review);
2. no mapping key survives in any text file — and binary files, which are not
   rewritten, are scanned for identifiers too and flagged as warnings;
3. line counts, timestamp counts, short-numeric-token counts (counters, PIDs,
   sizes) and the XML tag sequence are identical on both sides;
4. binary files are byte-identical; archive members, order and metadata match.

The web UI shows the verdict, per-file status, and a side-by-side diff with
the replaced spans highlighted (red outline = change the mapping does not explain).

**Delete the original after a clean verification** (on by default for
anonymize jobs): once the compare finds no error, the un-anonymized upload and
its extracted tree are removed from the server; only the anonymized archive,
the mapping and the reports remain. If the check finds problems, the original
is kept for review and the job says why — a *delete original now* button does
it once you have looked. CLI: `--verify --delete-original`.

New to TSFs? [docs/TSF-GUIDE.md](docs/TSF-GUIDE.md) explains what a tech
support file contains, where each kind of information lives, which daemon
log to read for which problem, and how to read an anonymized one.

## Run it

```bash
export TSF_UID=$(id -u) TSF_GID=$(id -g)
docker compose up -d --build
open http://127.0.0.1:8096
```

Uploads, extracted trees and outputs live in `./data/jobs/<id>/`. A 300 MB TSF
extracts to ~1.5 GB, kept twice (original + anonymized) so the diff viewer can
read them — use *free disk* on a job or delete it when done.

CLI (same code, no container):

```bash
pip install -e ".[dev]"
tsf-anonymizer anonymize in.tgz --verify --report integrity.json [--delete-original]
tsf-anonymizer compare in.tgz in_anon.tgz --mapping in_anon.mapping.json
tsf-anonymizer anonymize second.tgz --seed-mapping in_anon.mapping.json   # same customer, same pseudonyms
tsf-anonymizer serve --data-dir ./data
```

`--verify` / `compare` exit 2 when the integrity report has errors.

## Measured on a real TSF

PA-440, PAN-OS 12.1, 155 MB archive, 562 members, 1.2 GB extracted, 508 files
(2026-08-30, one core):

| | |
|---|---|
| anonymize + verify | ~10 min |
| mapping | 54 148 IPs · 202 objects · 54 FQDNs · 65 e-mails · 10 serials · 4 usernames |
| changed lines | 891 914 — **100 % explained by the mapping** |
| surviving identifiers (text) | **0** |
| binary files | 42, all byte-identical; 36 embed identifiers (`rule-hit-count.bin`, `wtmp`, `sa*`, `sslvpn-task.log`) |
| archive | same 562 members, same order, same metadata |

The compare mode found twelve defects in the anonymizer inherited from
TAC-MAN before that table read this way — rewritten XML tags, the App-ID
catalog registered as customer objects, chained pseudonyms, counters taken for
serials, URLs left untouched, an apex domain never mapped. They are recorded
as invariants in [CLAUDE.md](CLAUDE.md).

## Known limitations

- **A hostname that appears only in logs and never in a config is not
  redacted.** Named objects and FQDNs are discovered from the XML prescan;
  IPs, e-mails, serials and `user '…'` patterns are matched by shape
  everywhere. Free text (login banners, rule descriptions, comments) can
  carry a company name nothing matches.
- **Free text is not scanned.** Rule descriptions, comments, login banners
  can carry a company name that nothing matches. `<contact>` / `<full-name>`
  are anonymized.
- **A customer address inside our fake ranges (100.64/10, RFC 5737) is a
  collision.** It is still replaced, but the same string then also appears as
  somebody else's pseudonym; the report lists these under *mapping collisions*.
- **Binary files are not rewritten.** `rule-hit-count.bin`, sqlite databases
  or core dumps may embed rule names or IPs; the compare report lists which
  ones. Remove them from the archive if that matters.
- Usernames are only caught in the log phrasings the regex knows
  (`for user 'x'`, `user: 'x'`, …). Config-declared users are caught as named
  objects.
- IPv6 is not anonymized; neither are addresses rendered as byte arrays in
  Go debug output (`[0 0 … 255 255 10 0 0 254]`).
- **The compare mode only knows the mapping.** It proves every change is
  mapping-driven and that no mapped value survives; it cannot know that a
  string it never mapped is the customer's name. A raw `grep` of the
  anonymized tree for the customer name, domain and site names is the check
  to run on top — it is how the apex-domain gap was found.
- No authentication on the web UI — bind to loopback (the default) or put a
  proxy in front.

## Tests

```bash
pytest
```
