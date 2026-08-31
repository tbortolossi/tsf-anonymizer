#!/usr/bin/env python3
"""Fail when something that looks like a *real* identifier is about to be
committed: a routable IPv4, an e-mail or host name outside the synthetic
vocabulary, a PAN-OS-shaped serial, a ``DOMAIN\\user`` login — or anything
listed in the private denylist.

Why a script and not a rule: the repository's own doctrine is that nothing
from a real tech support file enters a test, a comment or a doc, and the
pre-publication scan of 2026-08-31 found several values that had — a
registered lab domain, a cloud IP, a device serial, a surname. Humans read
past them; this does not.

Usage::

    scripts/check-identifiers.py                # every git-tracked file
    scripts/check-identifiers.py FILE...        # what pre-commit passes
    scripts/check-identifiers.py --author       # also the git author e-mail

Two lists steer it:

* ``scripts/identifier-allowlist.txt`` — committed. The synthetic vocabulary
  (acme-corp.fr, 001901000123, …) and the vendor domains the docs cite. A
  host name passes when it *or any parent domain* is listed.
* ``.identifier-denylist`` at the repository root (git-ignored), or
  ``$XDG_CONFIG_HOME/tsf-anonymizer/denylist`` — never committed. One literal
  per line, matched case-insensitively anywhere: put your own domains,
  serials, logins and e-mail address there. ``--author`` checks the git
  identity against it too.

Exit status 1 on any finding, 0 otherwise. Reserved ranges (RFC 1918, 5737,
2544, 6598, loopback, link-local, multicast) and the RFC 2606 TLDs
(``.example``, ``.test``, ``.invalid``) never need listing.
"""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALLOWLIST = ROOT / "scripts" / "identifier-allowlist.txt"
DENYLISTS = (
    ROOT / ".identifier-denylist",
    Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config")) / "tsf-anonymizer" / "denylist",
)

# Paths never scanned: binaries, lockfile, the allowlist itself.
SKIP_PARTS = {".git", "data", "certs", ".venv", "node_modules"}
SKIP_SUFFIXES = {".png", ".jpg", ".gif", ".ico", ".woff", ".woff2", ".tgz", ".gz", ".bundle", ".lock"}
SKIP_FILES = {"uv.lock", "identifier-allowlist.txt"}

# Public TLDs worth a look. Two-letter codes that double as attribute names
# (`.co`, `.in`, `.me`, `.it`, `.at`, `.no`, `.us`…) and words code writes
# after a dot (`.info`, `.app`, `.home`, `.dev`) are left out on purpose:
# they drown the signal. `.local`, `.lan`, `.corp`, `.internal` are the
# Windows-domain suffixes a TSF is full of.
TLDS = ("com|net|org|fr|io|de|uk|eu|ch|be|nl|es|ru|cn|biz|cloud|ovh|xyz|online|site|"
        "tech|ai|ca|lu|pt|pl|se|dk|fi|ie|jp|kr|br|au|nz|edu|gov|mil|local|lan|corp|internal")
RFC2606 = ("example", "test", "invalid", "localhost")

IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@((?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,})")
FQDN_RE = re.compile(r"(?<![\w.-])((?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+"
                     rf"(?:{TLDS}|{'|'.join(RFC2606)}))(?![\w-])", re.IGNORECASE)
SERIAL_RE = re.compile(r"(?<![\d.])0\d{11}(?![\d.])")
# DOMAIN\user — a doubled backslash in code (a string literal; a single one
# is `\n` or a regex escape there), one or two in prose.
CODE_SUFFIXES = {".py", ".sh", ".js", ".css", ".html", ".yml", ".yaml", ".toml"}
NETBIOS_PY_RE = re.compile(r"(?<![\w\\])([A-Za-z][A-Za-z0-9-]{1,14})\\\\([A-Za-z][A-Za-z0-9._-]{2,})")
NETBIOS_RE = re.compile(r"(?<![\w\\])([A-Za-z][A-Za-z0-9-]{1,14})\\{1,2}([A-Za-z][A-Za-z0-9._-]{2,})")

RESERVED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
    "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16",
    "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4",
    "255.255.255.255/32",
)]


def load_list(paths: tuple[Path, ...] | Path) -> set[str]:
    out: set[str] = set()
    for p in (paths,) if isinstance(paths, Path) else paths:
        if p.is_file():
            for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.split("#", 1)[0].strip().lower()
                if line:
                    out.add(line)
    return out


def domain_allowed(domain: str, allow: set[str]) -> bool:
    d = domain.lower().rstrip(".")
    parts = d.split(".")
    if parts[-1] in RFC2606:
        return True
    return any(".".join(parts[i:]) in allow for i in range(len(parts)))


def ip_public(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False  # 999.1.1.1 and friends
    return not any(ip in n for n in RESERVED)


def scan_line(line: str, *, allow: set[str], deny: set[str], code: bool) -> list[str]:
    hits: list[str] = []
    low = line.lower()
    for d in deny:
        if d in low:
            hits.append(f"denylisted: {d!r}")
    for m in IPV4_RE.finditer(line):
        if ip_public(m.group(0)) and m.group(0) not in allow:
            hits.append(f"public IPv4: {m.group(0)}")
    for m in EMAIL_RE.finditer(line):
        if not domain_allowed(m.group(1), allow) and m.group(0).lower() not in allow:
            hits.append(f"e-mail: {m.group(0)}")
    for m in FQDN_RE.finditer(line):
        if not domain_allowed(m.group(1), allow):
            hits.append(f"host name: {m.group(1)}")
    for m in SERIAL_RE.finditer(line):
        if m.group(0) not in allow:
            hits.append(f"serial-shaped: {m.group(0)}")
    for m in (NETBIOS_PY_RE if code else NETBIOS_RE).finditer(line):
        if m.group(1).lower() not in allow:
            hits.append(f"DOMAIN\\user: {m.group(0)}")
    return hits


def skip(path: Path) -> bool:
    rel = path.as_posix()
    parts = set(rel.split("/"))
    return (bool(parts & SKIP_PARTS) or rel.startswith(("docs/private/", "docs/screenshots/"))
            or path.suffix.lower() in SKIP_SUFFIXES or path.name in SKIP_FILES)


def scan_file(path: Path, *, allow: set[str], deny: set[str]) -> list[str]:
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    if b"\0" in raw[:8192]:
        return []
    text = raw.decode("utf-8", errors="replace")
    code = path.suffix.lower() in CODE_SUFFIXES
    out = []
    for n, line in enumerate(text.splitlines(), 1):
        for hit in scan_line(line, allow=allow, deny=deny, code=code):
            out.append(f"{path.as_posix()}:{n}: {hit}")
    return out


def tracked_files() -> list[Path]:
    res = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=True)
    return [ROOT / p for p in res.stdout.decode().split("\0") if p]


def git_identities() -> dict[str, str]:
    """Author and committer identity as git would record them. `git var`
    fails on a machine with no user.name (a CI runner), so fall back to the
    environment and the config instead of reporting nothing."""
    out: dict[str, str] = {}
    for role in ("AUTHOR", "COMMITTER"):
        res = subprocess.run(["git", "var", f"GIT_{role}_IDENT"], cwd=ROOT, capture_output=True, text=True)
        ident = res.stdout.strip() if res.returncode == 0 else ""
        if not ident:
            cfg = subprocess.run(["git", "config", "user.email"], cwd=ROOT, capture_output=True, text=True)
            ident = " ".join(x for x in (os.environ.get(f"GIT_{role}_NAME", ""),
                                         os.environ.get(f"GIT_{role}_EMAIL", cfg.stdout.strip())) if x)
        out[role] = ident
    return out


def author_hits(deny: set[str]) -> list[str]:
    out = []
    for role, ident in git_identities().items():
        low = ident.lower()
        for d in deny:
            if d in low:
                out.append(f"git {role.lower()} identity matches denylisted {d!r} — set "
                           "`git config user.email` to your GitHub noreply address")
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("paths", nargs="*", help="files to scan (default: every git-tracked file)")
    ap.add_argument("--author", action="store_true", help="also check the git author/committer identity")
    args = ap.parse_args(argv)

    allow = load_list(ALLOWLIST)
    deny = load_list(DENYLISTS)
    paths = [Path(p).resolve() for p in args.paths] if args.paths else tracked_files()
    hits: list[str] = []
    for p in paths:
        rel = p.relative_to(ROOT) if p.is_relative_to(ROOT) else p
        if p.is_file() and not skip(rel):
            hits.extend(h.replace(p.as_posix(), rel.as_posix(), 1) for h in scan_file(p, allow=allow, deny=deny))
    if args.author:
        hits.extend(author_hits(deny))
    for h in hits:
        print(h)
    if hits:
        print(f"\n{len(hits)} finding(s). Synthetic value that is fine? Add it to "
              f"{ALLOWLIST.relative_to(ROOT)}. Real one? Replace it — and add it to your private "
              f".identifier-denylist so it never comes back.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
