# Security policy

tsf-anonymizer exists to keep customer identity out of the files people
share for troubleshooting. A defect in it is therefore a security matter
twice over: the tool itself handles un-anonymized archives, and its output
is trusted to contain nothing identifying. This page says what the project
considers a vulnerability, how to report one, and what is deliberately out
of scope.

## Reporting a vulnerability

**Do not open a public issue for a security problem.** Use GitHub's private
vulnerability reporting:

<https://github.com/tbortolossi/tsf-anonymizer/security/advisories/new>

You will get an acknowledgement within 7 days and a fix or a decision within
30 days for confirmed reports (this is a volunteer-maintained project; the
timeline is a commitment, not an SLA). Credit is given in the release notes
unless you ask otherwise.

**Never attach a real tech support file, a mapping, or an excerpt of one.**
Genericize: the *shape* of what leaked (`a hostname glued to an underscore
inside a nginx log line`) is what fixes the bug, never the value. The
`tsf-anonymizer mock-tsf` archive is the reproducer to build on — extend it
with a synthetic line that shows the pattern.

## What counts as a vulnerability

- **An identifier class that survives anonymization** in a case the tool
  claims to handle (see the table in the README and the invariants in
  [CLAUDE.md](CLAUDE.md)): an IP, hostname, FQDN, e-mail, username, serial
  or named object left in clear, or replaced by a pseudonym that reveals it
  (a chained or truncated replacement, a fake that collides with an original
  without being reported as a collision).
- **A verification that lies**: the compare mode reporting *OK* on an
  archive where a mapped value survives, where a change is not explained by
  the mapping, or where structure was lost.
- **A mapping that travels with the output**: any path by which the
  `*.mapping.json` sidecar — the key that reverses every pseudonym — ends up
  inside or next to the anonymized archive without the operator asking.
- **Web UI**: authentication bypass on any route (every route is behind
  HTTP Basic auth as soon as `TSF_PASSWORD` is set — no exemptions, health
  probe and static files included), path traversal through job ids, file
  names or diff paths, a way to read another job's input or mapping, or a
  TLS fallback to plain HTTP that the operator did not opt into.
- **Archive handling**: a crafted `.tgz` escaping the extraction directory,
  or making the service write outside `TSF_DATA_DIR`.

## What is documented, not a vulnerability

The README's *Known limitations* and the *Known limitations* section of
CLAUDE.md list what the tool does not do, on purpose or for lack of a
reliable heuristic — hostnames that appear only in free text, IPv6,
organisation names in certificate subjects, identifiers embedded in binary
files (flagged by the compare, redactable with `--redact-binaries`). A report
about one of these is a welcome feature request, not a security advisory.

The web UI's threat model is also documented and deliberate:

- **One shared account, LAN-grade.** HTTP Basic auth with a single
  username/password, no rate limiting on failed attempts, no session
  revocation, no per-user audit trail. Whoever has the password can download
  the un-anonymized archive and its mapping. Anything wider than a trusted
  LAN belongs behind a reverse proxy that adds what is missing.
- **Bound to loopback by default**, TLS mandatory as soon as a certificate
  is configured and *fail-closed* when it is missing. `TSF_BIND_ADDR` and
  `TSF_TLS_CERT=` (empty) are explicit opt-outs.
- **The self-signed CA** is trusted only where you imported it. A browser
  warning clicked through proves nothing about who answered.

## Supported versions

Only the latest release on the `0.x` line receives fixes. There is no
long-term support branch: upgrade to the newest version before reporting.

| version | supported |
| --- | --- |
| latest `0.x` release | yes |
| anything older | no |

## Handling your own data safely

Whatever the tool's correctness, the operator's practices decide whether a
customer's identity is protected:

- Keep the `*.mapping.json` with the customer's material, never with the
  anonymized archive.
- Run a raw `grep` of the anonymized tree for the customer's name, domains
  and site names before sharing it: the compare mode proves *every change is
  mapping-driven*, it cannot know that a string it never mapped is a name.
- Leave *delete the original after a clean verification* on, or delete
  `data/jobs/<id>/input` yourself once the job is done.
- Use a dedicated data directory on an encrypted volume; `./data` is a bind
  mount, and the container runs as your user so you can wipe it without
  `sudo`.
