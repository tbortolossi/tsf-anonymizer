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
cat > .env <<EOF          # gitignored; compose reads it automatically
TSF_UID=$(id -u)
TSF_GID=$(id -g)
TSF_PASSWORD=$(python3 -c "import secrets;print(secrets.token_urlsafe(18))")
EOF
scripts/make-tls-cert.sh              # TLS material in ./certs (gitignored)
docker compose up -d --build
open https://127.0.0.1:8096           # user: admin, password: the one in .env
```

Two things are required, both by design, because this UI serves the
*un*-anonymized archive and the mapping that reverses every pseudonym:

- **`TSF_PASSWORD`** — HTTP Basic auth on every route, `/api/health` and
  `/static` included. Compose refuses to start without it. `TSF_USERNAME`
  defaults to `admin`.
- **A certificate** — `scripts/make-tls-cert.sh` creates a local CA and a
  server certificate for the addresses the UI answers on. A *missing*
  certificate stops the container rather than quietly downgrading to plain
  HTTP; `TSF_TLS_CERT=` (empty) is the explicit opt-out.

Import `certs/ca.crt` into the browser or OS trust store, once per machine,
and the padlock is green. Re-running the script reissues the server
certificate and keeps the CA, so the import holds. With a certificate from a
real CA, point `TSF_TLS_CERT` / `TSF_TLS_KEY` at it instead.

To reach the UI from another machine on a trusted LAN, add its address to
`.env`, reissue the certificate for that name, and recreate:

```bash
echo "TSF_BIND_ADDR=10.0.0.246" >> .env    # or 0.0.0.0 for every interface
scripts/make-tls-cert.sh
docker compose up -d --force-recreate
```

Note that publishing on a LAN address means the port is *only* on that
address: use `https://<that address>:8096` from the host too.

### Where the archives live

Everything a job touches stays under `./data/jobs/<id>/` on the host —
gitignored, never sent anywhere:

```
data/jobs/<id>/input/       the TSF you uploaded, un-anonymized
               work/orig/   its extracted tree      } deleted by "free disk"
               work/anon/   the anonymized tree     } (the diff viewer needs them)
               output/      <name>_anon.tgz, <name>_anon.mapping.json,
                            anonymize-report.json, integrity-report.json
               job.json     status, summaries, batch and seed of the job
```

A 300 MB TSF extracts to ~1.5 GB, kept twice so the diff viewer can read both
sides. *Delete the original after a clean verification* (checked by default)
removes `input/` and `work/orig/` as soon as the integrity check comes back
clean; when it does not, the original is kept for review and the job says so.

### Batches

Drop several TSFs at once. They are uploaded and processed one at a time, and
you choose what the batch shares:

- **One shared mapping** — the same customer across several archives: each job
  seeds from the previous one, so an identifier keeps the same pseudonym
  everywhere and the mapping keeps growing. A job that fails is stepped over,
  not cascaded.
- **A separate mapping per TSF** — unrelated archives: nothing links an
  identifier from one to another.

An uploaded `mapping.json` seeds the first archive of the batch and travels
down the chain, which is how a TSF taken next month keeps last month's
pseudonyms.

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
- The web UI's auth is a single shared account: no per-user audit trail, no
  rate limiting on failed attempts, no session revocation. TLS protects the
  password on the wire and the archives in transit, but anyone who has that
  one password can download the un-anonymized archive and the mapping that
  reverses every pseudonym. The default self-signed CA is trusted only on the
  machines where you imported it — a browser warning you click through
  proves nothing about who answered.

## Tests

```bash
pytest
```
