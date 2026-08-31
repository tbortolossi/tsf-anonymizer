"""Anonymization core.

Derived from TAC-MAN's ``libs/anonymizer`` (Apache-2.0). What changed, and why:

* **Byte-exact round trip for everything that is not an identifier.** Text is
  decoded with ``surrogateescape`` and written back as bytes, so a Latin-1 byte
  in a log line, a ``\\r\\n`` line ending or a stray NUL-free control character
  comes out exactly as it went in. ``Path.read_text``/``write_text`` silently
  normalised line endings and replaced undecodable bytes with U+FFFD, which is
  a data change the compare mode would (rightly) flag.
* **The output archive keeps the input's member order and metadata.** Repack
  iterates the original ``TarInfo`` list and only swaps the payload, so mode,
  mtime, uid/gid and order are preserved. ``tar.add(dir)`` re-walked the
  filesystem and produced a different archive layout.
* **Serials are pre-registered from the config, and the fallback regex no
  longer eats epoch-millisecond timestamps.** ``\\d{12,15}`` matched every
  13-digit epoch-ms value in a log, turning timestamps into fake serials.
* **Structured result instead of prints.** The web UI and the compare mode
  need per-file outcomes and per-category counts.
* **Path-traversal-safe extraction** (symlinks, ``..``, absolute members).
"""

from __future__ import annotations

import copy
import gzip
import ipaddress
import json
import logging
import multiprocessing
import re
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ProcessPoolExecutor
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Iterable, Optional

logger = logging.getLogger(__name__)

ProgressFn = Callable[[str, int, int, str], None]
"""progress(phase, done, total, message)"""


def _noop_progress(phase: str, done: int, total: int, message: str) -> None:
    pass


# ---------------------------------------------------------------------------
# Binary file detection
# ---------------------------------------------------------------------------

# .ebl is deliberately absent: an EDL cache (vsys1_<name>.ebl) is a plain
# text IP list — 340 identifiers in one on a real TSF.
BINARY_EXTENSIONS = {
    ".bin", ".dat", ".db", ".sqlite", ".png", ".jpg", ".jpeg",
    ".gif", ".ico", ".pdf", ".zip", ".tar", ".rpm", ".deb", ".so", ".a",
    ".pyc", ".pyo", ".whl", ".egg", ".core", ".pcap", ".cap",
}


def is_binary_bytes(chunk: bytes) -> bool:
    """Text, or a binary format whose bytes must not be rewritten?

    A stray NUL used to mean binary, which left every `slot<n>-console-output.log`
    (one NUL in 4 KB, 200 identifiers) untouched. Measured on ~700 binary-
    classified files of eight real TSFs: text with a few NULs has ≤ 2 % of
    them, almost no other control bytes and a newline every few hundred
    bytes; real binary formats (`sslvpn-task.log` GpTaskStat records: 5 %
    NUL / 16 % control, `wtmp`: 90 % NUL, a zip: 10 % control) fail at least
    one of the three. Rewriting a length-prefixed format would corrupt it,
    so the NUL-tolerant branch is the strict one.
    """
    if not chunk:
        return False
    n = len(chunk)
    nul = chunk.count(0)
    ctrl = sum(1 for b in chunk if (b < 9 and b) or (13 < b < 32) or b == 127)
    if nul == 0:
        return ctrl / n > 0.30
    return not (nul / n <= 0.02 and ctrl / n <= 0.05 and chunk.count(b"\n") >= 8)


def is_binary_file(path: Path) -> bool:
    if path.suffix.lower() in BINARY_EXTENSIONS:
        return True
    try:
        with open(path, "rb") as f:
            return is_binary_bytes(f.read(4096))
    except Exception:
        return True


# ---------------------------------------------------------------------------
# PAN-OS built-in object names — never anonymize these
# ---------------------------------------------------------------------------

BUILTIN_OBJECTS = {
    "any", "trust", "untrust", "outside", "inside", "mgmt", "loopback",
    "tunnel", "vlan", "application-default", "interzone-default", "intrazone-default",
    "service-http", "service-https", "service-ftp", "service-smtp", "service-dns",
    "reject", "deny", "allow", "drop", "default", "shared", "localhost",
    "localhost.localdomain", "vsys1", "vsys2", "vsys3", "vsys4",
    "panorama", "admin", "root", "system", "pre-logon", "none",
    "yes", "no", "true", "false",
    # "www" as a service/category name is not a customer identifier, and
    # replacing it rewrote http://www.w3.org in every vendor XML namespace —
    # 11 "XML tag sequence differs" errors per box on a real batch.
    "www",
}

# Login names that are log vocabulary, not people: brute-force attempts on an
# exposed GP portal show up as `failed authentication for user 'error'`
# (also 'request', 'block', 'usr' on a real TSF), and replacing those words
# *everywhere* rewrote every standalone "error" in every log — 60 571
# unexplained lines. A word that identifies nobody needs no pseudonym.
_USER_STOPWORDS = {
    # seen as brute-force guesses on real TSFs
    "error", "request", "block", "usr", "port",
    # log vocabulary
    "user", "username", "login", "logout", "unknown", "invalid", "failed",
    "success", "warning", "info", "debug", "password", "session", "service",
    "config", "status", "level", "count", "system", "default", "none", "null",
    # the usual login-guess list of any exposed portal
    "test", "test1", "guest", "guest1", "demo", "temp", "tmp", "backup",
    "printer", "scanner", "camera", "oracle", "postgres", "mysql", "ftp",
    "ftpuser", "ssh", "vpn", "pi", "ubuntu", "support", "sales", "marketing",
    "office", "manager", "operator", "monitor", "nagios", "zabbix", "cisco",
    "web", "mail", "email", "sysadmin", "administrator", "superuser",
    "anonymous", "nobody", "daemon", "bin", "sys", "adm", "git", "jenkins",
    "docker", "tomcat", "apache", "nginx", "student", "staff", "remote",
    "access", "security", "firewall", "router", "switch", "ubnt", "user1",
}

# PAN-OS hardware interface name pattern — keep as-is (not customer-identifying,
# required for counter/interface matching downstream)
_PANOS_INTF_RE = re.compile(
    r"^(?:ethernet\d+/\d+(?:\.\d+)?"
    r"|ae\d+(?:\.\d+)?"
    r"|tunnel\.\d+"
    r"|loopback\.\d+"
    r"|vlan\.\d+"
    r"|hsci\d*"
    r")$",
    re.IGNORECASE,
)


def _is_panos_interface(name: str) -> bool:
    return bool(_PANOS_INTF_RE.match(name))


# Well-known vendor / RFC domains — keep as-is
VENDOR_DOMAINS = {
    "paloaltonetworks.com", "google.com", "microsoft.com", "amazonaws.com",
    "cloudflare.com", "akamai.com", "office365.com", "microsoftonline.com",
    "wildfire.paloaltonetworks.com", "updates.paloaltonetworks.com",
    "license.paloaltonetworks.com", "autofocus.paloaltonetworks.com",
    "example.com", "test.com", "anon.internal", "corp.local",
    "pool.ntp.org", "ntp.org",
}


# ---------------------------------------------------------------------------
# Named object categories to extract from XML
# ---------------------------------------------------------------------------

NAMED_OBJ_PATHS = [
    ("address",                "addr"),
    ("address-group",          "addr-grp"),
    ("service",                "svc"),
    ("service-group",          "svc-grp"),
    ("application-group",      "app-grp"),
    ("application-filter",     "app-filter"),
    ("schedule",               "sched"),
    ("zone",                   "zone"),
    ("virtual-router",         "vr"),
    ("interface",              "intf"),
    ("gateway",                "gw"),
    ("ike-gateway",            "ike-gw"),
    ("tunnel",                 "tunnel"),
    ("crypto-profiles",        "crypto"),
    ("ike-crypto-profile",     "ike-crypto"),
    ("ipsec-crypto-profile",   "ipsec-crypto"),
    ("authentication-profile", "auth-prof"),
    ("server-profile",         "srv-prof"),
    ("authentication-sequence", "auth-seq"),
    ("mfa-vendor-type",        "mfa"),
    ("admin",                  "admin"),
    ("user",                   "user"),
    ("user-group",             "grp"),
    ("device-group",           "dg"),
    ("template",               "tmpl"),
    ("template-stack",         "tmpl-stk"),
    ("log-forwarding",         "log-fwd"),
    ("email-server",           "mail-srv"),
    ("syslog-server",          "syslog-srv"),
    ("snmp-trap",              "snmp"),
    ("rules",                  "rule"),
    ("profiles",               "prof"),
    ("qos-profile",            "qos"),
    ("profile-group",          "prof-grp"),
    ("gateway",                "gp-gw"),
    ("portal",                 "gp-portal"),
    ("tunnel-interface",       "tun-intf"),
]

CATEGORY_PREFIX = {
    "addr": "ADDR", "addr-grp": "ADDR-GRP", "svc": "SVC", "svc-grp": "SVC-GRP",
    "app-grp": "APP-GRP", "zone": "ZONE", "vr": "VR", "intf": "INTF",
    "tun-intf": "TUN-INTF", "gw": "GW", "ike-gw": "IKE-GW", "tunnel": "TUNNEL",
    "auth-prof": "AUTH-PROF", "srv-prof": "SRV-PROF", "auth-seq": "AUTH-SEQ",
    "dg": "DG", "tmpl": "TMPL", "rule": "RULE", "qos": "QOS", "admin": "ADMIN",
    "user": "USR", "grp": "GRP", "gp-gw": "GP-GW", "gp-portal": "GP-PORTAL",
    "log-fwd": "LOG-FWD", "mail-srv": "MAIL-SRV",
}

MAPPING_CATEGORIES = (
    "ip_addresses", "usernames", "fqdns", "emails", "named_objects", "serial_numbers",
)



# ---------------------------------------------------------------------------
# Trie regex — one C-level pass over the text instead of a Python callback per
# token. Measured on a real 155 MB TSF (1.2 GB of text): the per-token
# dict-lookup pass ran for 11+ minutes before being killed; the trie pass is
# seconds. The trie prefers the longest key at every position, so a key that
# is a prefix of another ("GW-Paris" / "GW-Paris-Primary") never wins over it.
# ---------------------------------------------------------------------------

def trie_regex(words: Iterable[str]) -> str:
    """Regex source matching any of ``words`` (longest alternative first)."""
    trie: dict = {}
    for w in words:
        node = trie
        for ch in w:
            node = node.setdefault(ch, {})
        node[""] = {}

    def render(node: dict) -> str:
        terminal = "" in node
        alts = [re.escape(ch) + render(child) for ch, child in sorted(node.items()) if ch != ""]
        if not alts:
            return ""
        if len(alts) == 1 and not terminal:
            return alts[0]
        return "(?:" + "|".join(alts) + ")" + ("?" if terminal else "")

    return render(trie) if trie else "(?!)"


# ---------------------------------------------------------------------------
# Detection regexes — module level so the (stateless) parallel detection
# workers can use them without carrying an Anonymizer across processes.
# ---------------------------------------------------------------------------

# Not preceded by a digit or dot, not followed by a digit or by
# ".<digit>" — so 10.1.2.3.4 is not half-rewritten, but "peer 10.0.0.5."
# at the end of a sentence is.
_IP_RE = re.compile(
    r"(?<![.\d])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/\d{1,2})?(?!\d)(?!\.\d)"
)
_USER_PHRASE_RE = re.compile(
    r"(?:authenticated\s+for\s+user\s+['\"]"
    r"|for\s+user\s+['\"]"
    r"|(?:non-admin\s+)?user(?:name)?\s*[=:,\s]+['\"]"
    r"|user\s+thru\s+\S+\s+['\"]"
    r")([a-zA-Z][a-zA-Z0-9._@-]{1,})['\"]?"
)
# Fallback for serials the config did not declare. 13- and 14-digit
# runs are deliberately NOT matched — 13 digits is an epoch in
# milliseconds — and neither is a 12-digit run starting 0000: those are
# zero-padded counters in `show counter` output (real TSF: 3 434 of
# them were "anonymized").
# A PAN-OS serial starts with 0 (hardware: 12 digits, e.g. 0019…,
# 0113…; VM-Series: 007 + 12). 486712289187-shaped 12-digit runs are
# App-ID ids and counters, and 2 397 of them were "serials" on the
# first real run.
# …and not a busybox date either: `sys.time.datetime-busybox:
# 040509422026` is MMDDhhmmYYYY, twelve digits starting with 0.
# Not right after a dot: logdb file names are `pan.000100628656.log`, and a
# real run turned thousands of those sequence numbers into fake serials —
# lines the compare then (rightly) could not explain, since its own numeric
# boundary already excluded a leading dot.
_SERIAL_FALLBACK_RE = re.compile(
    r"(?<![.\d])(?!(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?:[01]\d|2[0-3])[0-5]\d(?:19|20)\d\d(?!\d))"
    r"(0(?!000)\d{11}|007\d{12})(?!\d)"
)
# The domain may not start with an all-digit label and the match may not be
# glued to a "-word": sysd keys read `cfg.net.s6.eth2@252.acl-debug`
# (interface@vlan.acl) and every one became an e-mail — and "252.acl" a
# domain — on a real PA-7000 TSF. The price is a genuine `x@163.com`, which
# does not occur in firewall logs.
_EMAIL_RE = re.compile(
    r"\b([a-zA-Z0-9._%+\-]+)@((?!\d+\.)[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b(?![\-_]\w)"
)


def _valid_ipv4_octets(ip: str) -> bool:
    return all(p.isdigit() and 0 <= int(p) <= 255 for p in ip.split("."))


# ---------------------------------------------------------------------------
# Anonymizer state
# ---------------------------------------------------------------------------

class Anonymizer:
    """Consistent pseudonymizer. Call ``build_patterns()`` after the prescan."""

    # Wildcard / reserved IPs to keep as-is
    _SKIP_IPS = {
        "0.0.0.0", "255.255.255.255", "255.255.255.0", "255.255.0.0",
        "255.0.0.0", "224.0.0.0", "240.0.0.0", "255.255.255.128",
        "255.255.255.192", "255.255.255.224", "255.255.255.240",
        "255.255.255.248", "255.255.255.252", "255.255.255.254",
    }

    def __init__(self) -> None:
        self.ip_map: dict[str, str] = {}
        self.user_map: dict[str, str] = {}
        self.serial_map: dict[str, str] = {}
        self.named_obj_map: dict[str, str] = {}
        self.fqdn_map: dict[str, str] = {}
        self.email_map: dict[str, str] = {}

        self._priv_counter = 0
        self._pub_counter = 0
        self._user_counter = 0
        self._serial_counter = 0
        self._obj_counter = 0
        self._fqdn_counter = 0
        self._email_counter = 0

        self._obj_re: Optional[re.Pattern] = None
        self._cs_table: dict[str, str] = {}   # objects + usernames behind _obj_re
        self._fqdn_re: Optional[re.Pattern] = None
        self._known_serial_re: Optional[re.Pattern] = None
        self._user_trie_re: Optional[re.Pattern] = None
        self._built_for: tuple = ()
        # Every fake value ever produced. A later pass must never treat one as
        # an original (user 'Zone-A' → user 'OBJ-0002' → user001 chained two
        # pseudonyms and broke config↔log correlation on a real TSF).
        self._fakes: set[str] = set()

        # Per-call replacement tally, reset by anonymize_text().
        self.last_counts: dict[str, int] = {}

        # Frozen: the tables are complete (detection ran) and must not grow —
        # which is exactly what makes the rewrite a pure function, safe to
        # spread over processes. A value that *would* have been allocated is
        # left unchanged and recorded here; it should never happen, and the
        # caller surfaces it as a warning rather than silently diverging.
        self.frozen = False
        self.frozen_misses: set[str] = set()

        # Replace binary payloads that embed mapping identifiers with
        # REDACTED_PAYLOAD instead of shipping them untouched (sslvpn-task
        # logs carried ~27 000 identifiers per file on a real TSF). Off by
        # default: it deliberately loses data, so it is the operator's call.
        self.redact_binaries = False
        self._redaction_scanner: Optional[list[re.Pattern]] = None

        self._ip_re = _IP_RE
        self._user_re = _USER_PHRASE_RE
        self._serial_re = _SERIAL_FALLBACK_RE
        self._email_re = _EMAIL_RE

    # -- IP anonymization ---------------------------------------------------

    def _fake_private_ip(self) -> str:
        self._priv_counter += 1
        n = self._priv_counter
        second = 64 + ((n - 1) >> 16) % 64  # 100.64.x – 100.127.x (RFC 6598)
        return f"100.{second}.{(n >> 8) & 0xFF}.{n & 0xFF or 1}"

    def _fake_public_ip(self) -> str:
        self._pub_counter += 1
        n = self._pub_counter
        blocks = [(192, 0, 2), (198, 51, 100), (203, 0, 113)]  # RFC 5737
        b = blocks[(n - 1) // 256 % len(blocks)]
        return f"{b[0]}.{b[1]}.{b[2]}.{n % 256 or 1}"

    def anon_ip(self, ip_str: str) -> str:
        if ip_str in self._SKIP_IPS:
            return ip_str
        if ip_str in self.ip_map:
            return self.ip_map[ip_str]
        try:
            addr = ipaddress.ip_address(ip_str)
            if addr.is_loopback or addr.is_multicast or addr.is_unspecified or addr.is_reserved:
                return ip_str
            if addr.is_link_local:
                return ip_str
            if self.frozen:
                if ip_str not in self._fakes:
                    self.frozen_misses.add(ip_str)
                return ip_str
            gen = self._fake_private_ip if addr.is_private else self._fake_public_ip
            fake = gen()
            # A customer may use our fake ranges (100.64/10 is a common GP
            # pool). Never hand out a fake that is also an original we know.
            while fake in self.ip_map:
                fake = gen()
        except ValueError:
            return ip_str
        if ip_str in self._fakes:
            return ip_str
        self.ip_map[ip_str] = fake
        self._fakes.add(fake)
        return fake

    # -- Username anonymization ---------------------------------------------

    def anon_user(self, username: str) -> str:
        if (username.lower() in BUILTIN_OBJECTS or username.lower() in _USER_STOPWORDS
                or username in self._fakes or username.startswith(_VOCAB_PREFIXES)):
            return username
        # `user 'ehs'` where ehs is a GP portal domain: the FQDN pass owns
        # that identity — a second pseudonym here would be a dead mapping
        # entry (the FQDN pass runs first and always wins).
        if username.lower().rstrip(".") in self.fqdn_map:
            return username
        if username not in self.user_map:
            if self.frozen:
                self.frozen_misses.add(username)
                return username
            self._user_counter += 1
            self.user_map[username] = f"user{self._user_counter:03d}"
            self._fakes.add(self.user_map[username])
        return self.user_map[username]

    # -- FQDN anonymization -------------------------------------------------

    def anon_fqdn(self, fqdn: str) -> str:
        low = fqdn.lower().rstrip(".")
        if low in VENDOR_DOMAINS or any(low.endswith("." + d) for d in VENDOR_DOMAINS):
            return fqdn
        if low in BUILTIN_OBJECTS:
            return fqdn
        if low in self.fqdn_map:
            return self.fqdn_map[low]
        self._fqdn_counter += 1
        parts = low.split(".")
        fake = (
            f"host{self._fqdn_counter:03d}.anon.internal"
            if len(parts) > 1
            else f"host{self._fqdn_counter:03d}"
        )
        self.fqdn_map[low] = fake
        self._fakes.add(fake)
        return fake

    def register_fqdn(self, fqdn: str) -> None:
        """Register a FQDN and every parent domain down to the registrable
        one: igw.home-lab.example also yields home-lab.example, otherwise the apex
        survives in https://home-lab.example/… and *.home-lab.example (real TSF)."""
        self.anon_fqdn(fqdn)
        parts = fqdn.lower().rstrip(".").split(".")
        if any(not p for p in parts) or _FILE_SUFFIX_RE.search(fqdn):
            return  # "a..b", "x.conf.5.gz": a file name, not a domain
        for i in range(1, len(parts) - 1):
            parent = ".".join(parts[i:])
            if (parts[i] in _DC_STOPWORDS or len(parts[i]) < 2 or parts[i].isdigit()
                    or not any(c.isalpha() for c in parent)):
                continue
            self.anon_fqdn(parent)

    # -- Email anonymization ------------------------------------------------

    def anon_email(self, local: str, domain: str) -> str:
        # Case-insensitive key: JDupont@x and jdupont@x are one identity,
        # and two pseudonyms for it broke correlation on a real TSF (the
        # compare matches e-mails case-insensitively and could explain only
        # one of the two).
        original = f"{local}@{domain}".lower()
        if original in self.email_map:
            return self.email_map[original]
        if self.frozen:
            self.frozen_misses.add(original)
            return original
        self._email_counter += 1
        fake_domain = self.anon_fqdn(domain)
        fake = f"user{self._email_counter:03d}@{fake_domain}"
        self.email_map[original] = fake
        self._fakes.add(fake)
        return fake

    # -- Named object anonymization -----------------------------------------

    def register_named_object(self, name: str, category: str = "obj") -> str:
        if not name or len(name) < 2:
            return name
        if name.lower() in BUILTIN_OBJECTS:
            return name
        if _is_panos_interface(name):
            return name
        if name.isdigit() or _IP_LIKE_RE.match(name):
            return name
        if name in self.named_obj_map:
            return self.named_obj_map[name]
        self._obj_counter += 1
        if name in self._fakes:
            return name
        prefix = CATEGORY_PREFIX.get(category, "OBJ")
        self.named_obj_map[name] = f"{prefix}-{self._obj_counter:04d}"
        self._fakes.add(self.named_obj_map[name])
        return self.named_obj_map[name]

    # -- Serial number ------------------------------------------------------

    def anon_serial(self, serial: str) -> str:
        if serial in self.serial_map:
            return self.serial_map[serial]
        if serial in self._fakes:
            return serial
        if self.frozen:
            self.frozen_misses.add(serial)
            return serial
        self._serial_counter += 1
        # Same length, leading 9: no PAN-OS serial starts with 9, so a fake
        # cannot collide with a real one.
        fake = "9" + f"{self._serial_counter:0{len(serial) - 1}d}"
        self.serial_map[serial] = fake
        self._fakes.add(fake)
        return fake

    # -- Build compiled patterns (call once after all prescan) --------------

    def build_patterns(self) -> None:
        """Compile the replacement regexes. Call once after the prescan, and
        again after registering more names (from_mapping does)."""
        # A certificate entry named after its own CN is the same identity as
        # the FQDN; two pseudonyms for it broke correlation on a real TSF.
        for name in [n for n in self.named_obj_map if n.lower().rstrip(".") in self.fqdn_map]:
            del self.named_obj_map[name]
        if self.fqdn_map:
            # "/" before is allowed on purpose: https://vpn.acme.fr/ and
            # /path/to/vpn.acme.fr.csr must be rewritten; only </tag> is not.
            # "." after is allowed too — a sentence ends, a file has a suffix.
            # "." before is allowed: *.home-lab.example and sub.home-lab.example
            # must be rewritten when only the apex is known. A longer key
            # still wins — the scan is leftmost, so igw.home-lab.example is
            # matched at "igw" before the apex is ever tried.
            # "_" is a separator here, not a word character: a hostname cannot
            # contain one, and PAN-OS glues the device name with underscores
            # (techsupport_<devicename>_<date>.txt, in the member name and in
            # the text) — the one place the name survived a real run.
            self._fqdn_re = re.compile(
                r"(?<![A-Za-z0-9\-<])(?<!<\/)" + trie_regex(self.fqdn_map)
                + r"(?:(?![A-Za-z0-9\-=])|(?=(?:19|20)\d\d-\d\d-\d\d))(?!:\/\/)",
                re.IGNORECASE,
            )
        else:
            self._fqdn_re = None
        # An object whose name *embeds* a FQDN or an e-mail can never win: the
        # earlier pass rewrites that part first and the whole-name key is dead
        # — a mapping entry that never fires, and thousands of lines the
        # compare cannot explain ('Enloe Domain controllers' after 'Enloe'
        # became host1208, on a real TSF). The identifying part is owned by
        # the earlier pass; drop the dead key so the mapping stays honest.
        for name in [n for n in self.named_obj_map
                     if (self._fqdn_re and self._fqdn_re.search(n)) or _EMAIL_RE.search(n)]:
            del self.named_obj_map[name]
        # One case-sensitive trie for objects and usernames (objects win a
        # same-key collision, as in the compare's MappingIndex).
        self._cs_table = {**self.user_map, **self.named_obj_map}
        if self._cs_table:
            # A name is replaced only as a whole token: not inside a longer
            # word, not as one segment of a hyphenated compound ("web" in
            # "web-server-1"), not as a label of a dotted name on the left
            # ("x.Zone-A"). A dot *after* is fine — sentence ends.
            # "<" and "</" excluded before, "=" and "://" after: an object named
            # like an XML tag, an attribute or a URL scheme must not rewrite
            # <enabled>, name="…" or http://. Verified on a real TSF: it did.
            # The trailing boundary also accepts a glued timestamp:
            # md_out.log writes "…_com2026-04-05 09:38:00" with no separator,
            # and the customer name leaked inside it. A longer key that
            # really ends in a date is still preferred by the trie.
            # "(?<!//)": a name right after "//" is the start of a URL
            # authority (http://www.w3.org), never a standalone object —
            # rewriting one broke vendor XML namespaces on a real TSF.
            # "(?<=vsys\d_)": PAN-OS glues an object name to its vsys in file
            # names (vsys1_<EDL name>.ebl) — the one underscore that is a
            # separator, not part of a name.
            self._obj_re = re.compile(
                r"(?:(?<![\w.\-<])|(?<=vsys\d_))(?<!<\/)(?<!\/\/)" + trie_regex(self._cs_table)
                + r"(?:(?![\w\-=])|(?=(?:19|20)\d\d-\d\d-\d\d))(?!:\/\/)"
            )
        else:
            self._obj_re = None
        # Usernames (from the config's <users>/<admin> entries they are named
        # objects; from log phrasings they land here) are replaced wherever they
        # appear — UID="x", (x), x@host — not only in the phrasing that found them.
        self._user_trie_re = None  # folded into _obj_re (one trie, longest key wins)
        self._built_for = self._map_sizes()
        # Serials discovered in the config are replaced wherever they appear,
        # whatever their shape; the regex fallback below is stricter. Same
        # leading boundary as the compare's numeric pass — a dot before means
        # a file-name segment, not a serial.
        self._known_serial_re = (
            re.compile(r"(?<![.\d])" + trie_regex(self.serial_map) + r"(?!\d)")
            if self.serial_map else None
        )

    def _map_sizes(self) -> tuple:
        return (len(self.named_obj_map), len(self.fqdn_map), len(self.user_map),
                len(self.serial_map))

    def binary_embeds_identifier(self, raw: bytes) -> bool:
        """Does a binary payload contain a mapping key? Same boundary
        conventions as the compare's leak scan — deliberately *duplicated*,
        not shared: if this decided what the compare then verifies with the
        same code, a bug here would be invisible there."""
        if self._redaction_scanner is None:
            values = {v for table in (self.ip_map, self.user_map, self.fqdn_map,
                                      self.email_map, self.named_obj_map, self.serial_map)
                      for v in table.values()}
            num, cs, ci = [], [], []
            for k in list(self.ip_map) + list(self.serial_map):
                if len(k) >= 3 and k not in values:
                    num.append(k)
            for k in list(self.fqdn_map) + list(self.email_map):
                if len(k) >= 3 and k not in values:
                    ci.append(k)
            ci_low = {k.lower() for k in ci}
            for k in list(self.named_obj_map) + list(self.user_map):
                if len(k) >= 3 and k not in values and k.lower() not in ci_low:
                    cs.append(k)
            scanners = []
            if num:
                scanners.append(re.compile(r"(?<![.\d])" + trie_regex(num) + r"(?!\d)(?!\.\d)"))
            if cs:
                scanners.append(re.compile(
                    r"(?<![\w.\-<])(?<!<\/)" + trie_regex(cs)
                    + r"(?:(?![\w\-=])|(?=(?:19|20)\d\d-\d\d-\d\d))(?!:\/\/)"))
            if ci:
                scanners.append(re.compile(
                    r"(?<![\w\-<])(?<!<\/)" + trie_regex(ci)
                    + r"(?:(?![\w\-=])|(?=(?:19|20)\d\d-\d\d-\d\d))(?!:\/\/)", re.IGNORECASE))
            self._redaction_scanner = scanners
        text = raw.decode("latin-1")  # never fails; identifiers stay findable
        return any(rx.search(text) for rx in self._redaction_scanner)

    # -- Full text replacement ----------------------------------------------

    def _count(self, key: str) -> None:
        self.last_counts[key] = self.last_counts.get(key, 0) + 1

    def _replace_ips(self, text: str) -> str:
        def replace_match(m: re.Match) -> str:
            ip = m.group(1)
            cidr = m.group(2) or ""
            parts = ip.split(".")
            if not all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                return m.group(0)
            fake = self.anon_ip(ip)
            if fake != ip:
                self._count("ip_addresses")
            return fake + cidr
        return self._ip_re.sub(replace_match, text)

    def _replace_users(self, text: str) -> str:
        """Known usernames are replaced by the combined trie in
        _replace_named_objects. What is left here is discovery by log
        phrasing — frozen means the text-identity prescan ran and every
        username this regex can find is already in that trie, so re-scanning
        would be the single most expensive regex for zero effect. Unfrozen
        (direct API use, no prescan), it is how usernames get discovered at
        all — and a newly discovered one is replaced everywhere at the next
        rebuild (`_built_for`)."""
        if self.frozen:
            return text

        def replace_match(m: re.Match) -> str:
            full = m.group(0)
            user = m.group(1)
            fake = self.anon_user(user)
            if fake != user:
                self._count("usernames")
            return full.replace(user, fake, 1)
        return self._user_re.sub(replace_match, text)

    def _replace_emails(self, text: str) -> str:
        def replace_match(m: re.Match) -> str:
            self._count("emails")
            return self.anon_email(m.group(1), m.group(2))
        return self._email_re.sub(replace_match, text)

    def _replace_fqdns(self, text: str) -> str:
        if self._fqdn_re is None:
            return text

        def replace_match(m: re.Match) -> str:
            fake = self.fqdn_map.get(m.group(0).lower())
            if fake is None:
                return m.group(0)
            self._count("fqdns")
            return fake
        return self._fqdn_re.sub(replace_match, text)

    def _replace_named_objects(self, text: str) -> str:
        """Named objects *and* usernames, one trie: the longest key wins at
        every position whatever its category. Two tries in sequence let a
        service named `amanda` eat the first label of `amanda.hudspeth`
        (`SVC-17959.hudspeth` — the surname went out in clear on a real TSF);
        one trie is also what the compare's token pass has always done."""
        if self._obj_re is None:
            return text
        table, users = self._cs_table, self.user_map

        def replace_match(m: re.Match) -> str:
            key = m.group(0)
            fake = table.get(key)
            if fake is None:
                return key
            self._count("usernames" if key in users and key not in self.named_obj_map
                        else "named_objects")
            return fake
        return self._obj_re.sub(replace_match, text)

    def _replace_serials(self, text: str) -> str:
        def replace_match(m: re.Match) -> str:
            fake = self.anon_serial(m.group(1))
            if fake != m.group(1):
                self._count("serial_numbers")
            return fake

        def replace_known(m: re.Match) -> str:
            self._count("serial_numbers")
            return self.serial_map[m.group(0)]

        if self._known_serial_re is not None:
            text = self._known_serial_re.sub(replace_known, text)
        return self._serial_re.sub(replace_match, text)

    def anonymize_text(self, text: str) -> str:
        """Order matters: emails before FQDNs, FQDNs before named objects, IPs last."""
        self.last_counts = {}
        # A domain discovered through an e-mail, or a user through a log
        # phrasing, is added after build_patterns(); the compiled tries would
        # keep missing its bare occurrences (mail.ru, 19 survivals on a real
        # TSF). Recompile when a table grew — once per file at most.
        if self._built_for != self._map_sizes():
            self.build_patterns()
        text = self._replace_emails(text)
        text = self._replace_fqdns(text)
        text = self._replace_named_objects(text)
        text = self._replace_ips(text)
        text = self._replace_users(text)
        text = self._replace_serials(text)
        return text

    # -- Mapping ------------------------------------------------------------

    def get_mapping(self) -> dict:
        return {
            "ip_addresses":   dict(self.ip_map),
            "usernames":      dict(self.user_map),
            "fqdns":          dict(self.fqdn_map),
            "emails":         dict(self.email_map),
            "named_objects":  dict(self.named_obj_map),
            "serial_numbers": dict(self.serial_map),
        }

    @classmethod
    def from_mapping(cls, mapping: dict) -> "Anonymizer":
        """Rebuild an anonymizer whose tables are pre-filled — used to
        anonymize a second TSF from the same customer consistently."""
        anon = cls()
        anon.ip_map.update(mapping.get("ip_addresses", {}))
        anon.user_map.update(mapping.get("usernames", {}))
        anon.fqdn_map.update(mapping.get("fqdns", {}))
        # Older mappings may carry mixed-case e-mail keys; fold them so a
        # seeded run keeps one pseudonym per address.
        anon.email_map.update({k.lower(): v for k, v in mapping.get("emails", {}).items()})
        anon.named_obj_map.update(mapping.get("named_objects", {}))
        anon.serial_map.update(mapping.get("serial_numbers", {}))
        anon._priv_counter = sum(1 for v in anon.ip_map.values() if v.startswith("100."))
        anon._pub_counter = len(anon.ip_map) - anon._priv_counter
        anon._user_counter = len(anon.user_map)
        anon._serial_counter = len(anon.serial_map)
        anon._obj_counter = len(anon.named_obj_map)
        anon._fqdn_counter = len(anon.fqdn_map)
        anon._email_counter = len(anon.email_map)
        for table in (anon.ip_map, anon.user_map, anon.fqdn_map, anon.email_map,
                      anon.named_obj_map, anon.serial_map):
            anon._fakes.update(table.values())
        anon.build_patterns()
        return anon


# ---------------------------------------------------------------------------
# XML prescan
# ---------------------------------------------------------------------------

SENSITIVE_XML_FIELDS = {
    "common-name":      "fqdn",
    "issuer":           "cert",
    "subject":          "cert",
    "domain":           "domain",
    "base":             "dn",
    "bind-dn":          "dn",
    "address":          "fqdn",
    "to":               "email",
    "and-condition":    None,
    "recipient-emails": "email",
    "hostname":         "host",
    "devicename":       "host",
    "contact":          "person",   # admin contact (free text, a real name)
    "full-name":        "person",
    "serial":           "serial",
    "panorama-server":  "fqdn",
    "ntp-server-address": "fqdn",
    "primary-ntp-server": None,
}

_CERT_CN_RE = re.compile(r"(?<![A-Za-z])CN\s*=\s*([^,/\n]+)")
_DC_COMPONENT_RE = re.compile(r"DC=([^,]+)", re.IGNORECASE)
_EMAIL_IN_TEXT_RE = _EMAIL_RE
_IPV4_ONLY_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _extract_cert_identifiers(text: str, anon: Anonymizer) -> None:
    """Only the CN, and only when it is a hostname. O/OU/L/ST are prose
    ("GeoTrust Inc.", "Network Solutions L.L.C.") — the trusted root store in
    every config carries hundreds of public CA names, none of them customer
    identifiers, and registering them as FQDNs produced nothing but noise."""
    for m in _CERT_CN_RE.finditer(text):
        val = m.group(1).strip().strip('"')
        if "." in val and " " not in val and not _IPV4_ONLY_RE.match(val):
            anon.register_fqdn(val)


# DN components that are plain words, not identifiers. Registering "local" as
# a FQDN would rewrite every "local" in every log line.
_DC_STOPWORDS = {
    "local", "lan", "intra", "internal", "corp", "com", "net", "org", "edu", "gov",
    "ad", "ads", "dom", "domain", "int", "pri", "priv", "private", "home", "office",
}


def _extract_dn_identifiers(text: str, anon: Anonymizer) -> None:
    parts = [m.group(1) for m in _DC_COMPONENT_RE.finditer(text)]
    if parts:
        anon.register_fqdn(".".join(parts))
        # The last component is the TLD-ish suffix ("local", "com"): skip it.
        for part in parts[:-1]:
            low = part.lower()
            if len(part) > 2 and low not in BUILTIN_OBJECTS and low not in _DC_STOPWORDS:
                anon.register_fqdn(part)


# Entry names that are PAN-OS vocabulary rather than customer identifiers.
# Found on a real TSF: "http", "ftp", "pdf", "linux", "title", "archive" are
# entries under decoders / file types / applications, and replacing them
# rewrote every "http" in every log (and http:// in XML namespaces).
# "pan_devicetelem" is a system account. A customer zone named "lan" is
# kept too — that is the trade-off, and it is not an identifier.
_VOCAB_PARENTS = {
    "decoder", "application", "file-type", "dns-security-categories", "category",
    "threat-exception", "lists", "protocol", "signature", "botnet-domains",
    "config",  # <gp-app-config><config><entry name="connect-method"> — setting names
}
_VOCAB_NAME_RE = re.compile(r"^[a-z][a-z0-9]{0,11}$")
_VOCAB_PREFIXES = ("pan_", "panw-", "pan-")
# Parents whose entries are identities whatever their spelling: a lowercase
# admin "jmartin" is not vocabulary. Everything in NAMED_OBJ_PATHS plus
# the containers PAN-OS uses for accounts, servers and interfaces.
_IDENTITY_PARENTS = {t for t, _ in NAMED_OBJ_PATHS} | {
    "users", "certificate", "server", "ldap", "radius", "kerberos", "tacplus", "saml-idp",
    "local-user-database", "email", "syslog", "http", "snmptrap", "layer3", "units",
    "ethernet", "vlan", "aggregate-ethernet", "loopback", "ike-crypto-profiles",
    "ipsec-crypto-profiles", "ipsec", "vsys", "dynamic-user-group", "custom-url-category",
    "tag", "static-route", "bgp-peer", "peer", "peer-group", "dhcp", "reserved",
}
_IP_LIKE_RE = re.compile(
    r"^\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?(?:-\d{1,3}(?:\.\d{1,3}){3})?$"
)
_FQDN_LIKE_RE = re.compile(r"^(?=.*[A-Za-z])[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


def _is_vocabulary(name: str, parent_tag: str) -> bool:
    if name.startswith(_VOCAB_PREFIXES) or parent_tag in _VOCAB_PARENTS:
        return True
    if parent_tag in _IDENTITY_PARENTS:
        return False
    return _VOCAB_NAME_RE.match(name) is not None


# Subtrees that hold Palo Alto's own content, not the customer's: the
# App-ID / threat / URL-category catalog. A candidate config that embeds it
# registered 41 973 "objects" named Apple, Linux, bgp, enabled, … and the
# replacement then rewrote every <enabled> and <bgp> tag in every XML.
_SKIP_SUBTREES = {"predefined", "threats", "application-type"}


# <entry name="acme\jdupont"> (userinfo.xml): a DOMAIN\user spelling is two
# identities, not one. Registered whole, it becomes a mapping entry that can
# never win — the FQDN pass rewrites the domain part first — and on a real TSF
# that was 119 299 lines the compare could not explain.
_DOMAIN_USER_NAME_RE = re.compile(
    r"^([A-Za-z][A-Za-z0-9.-]{1,62})\\+([A-Za-z0-9][A-Za-z0-9._@$-]{0,63})$"
)


def _register_entry_name(name_attr: Optional[str], parent_tag: str, anon: Anonymizer) -> None:
    if not (name_attr and len(name_attr) >= 2 and name_attr.lower() not in BUILTIN_OBJECTS
            and not _is_vocabulary(name_attr, parent_tag)):
        return
    name_attr = name_attr.strip()
    du = _DOMAIN_USER_NAME_RE.match(name_attr)
    if du:
        domain, user = du.group(1), du.group(2)
        # A stopword domain ("corp", "local") is generic, like a zone named
        # "lan" — the user part is the identity either way.
        if domain.lower() not in _DC_STOPWORDS and domain.lower() not in BUILTIN_OBJECTS:
            anon.register_fqdn(domain)
        # A trailing "$" is the machine-account marker, not part of the name:
        # kept in the key, the whole key never fired (an object pass had
        # already rewritten the name in front of it) — one unexplained line
        # on a real TSF, and the "$" survives in the output regardless.
        anon.anon_user(user.rstrip("$"))
        return
    if _IP_LIKE_RE.match(name_attr):
        pass  # an address object named by its IP: the IP pass owns it
    elif _FQDN_LIKE_RE.match(name_attr) and not name_attr.lower().endswith((".log", ".xml")):
        anon.register_fqdn(name_attr)  # one identity, one pseudonym
    else:
        category = "obj"
        for obj_tag, cat in NAMED_OBJ_PATHS:
            if parent_tag == obj_tag:
                category = cat
                break
        anon.register_named_object(name_attr, category)


def _register_sensitive_field(tag: str, val: str, anon: Anonymizer) -> None:
    field_type = SENSITIVE_XML_FIELDS.get(tag)
    if not field_type:
        return
    # _IP_LIKE_RE, not _IPV4_ONLY_RE: an <address> holding "10.18.2.254/24"
    # is the IP pass's territory too — registered as a "FQDN" it became
    # host005.anon.internal and the /24 was lost (real TSF).
    if field_type == "fqdn":
        if "." in val and not val.startswith("DC=") and not _IP_LIKE_RE.match(val):
            anon.register_fqdn(val)
    elif field_type == "host":
        if len(val) > 2 and val.lower() not in BUILTIN_OBJECTS and not _IP_LIKE_RE.match(val):
            anon.register_fqdn(val)
    elif field_type == "cert":
        _extract_cert_identifiers(val, anon)
    elif field_type == "dn":
        _extract_dn_identifiers(val, anon)
    elif field_type == "domain":
        if len(val) > 2 and val.lower() not in BUILTIN_OBJECTS:
            anon.register_fqdn(val)
    elif field_type == "email":
        for m in _EMAIL_IN_TEXT_RE.finditer(val):
            anon.anon_email(m.group(1), m.group(2))
    elif field_type == "serial":
        if val.isdigit() and 8 <= len(val) <= 16:
            anon.anon_serial(val)
    elif field_type == "person":
        if len(val) > 1 and val.lower() not in BUILTIN_OBJECTS:
            anon.register_named_object(val, "user")


def _walk_xml(elem: ET.Element, anon: Anonymizer, parent_tag: str = "") -> None:
    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
    if tag in _SKIP_SUBTREES:
        return
    # <config><global> is the content catalog a candidate config embeds
    # (application, signature, iot-definitions, opswat, modification-history…):
    # 42 165 vendor names on a real box, against 345 customer objects under
    # <devices>/<shared>/<mgt-config>.
    if tag == "global" and parent_tag == "config":
        return

    if tag == "entry":
        _register_entry_name(elem.get("name"), parent_tag, anon)

    if elem.text and elem.text.strip():
        _register_sensitive_field(tag, elem.text.strip(), anon)

    for child in elem:
        _walk_xml(child, anon, parent_tag=tag)


def _salvage_prescan_xml(xml_path: Path, anon: Anonymizer) -> None:
    """Prescan the parseable prefix of a malformed XML — most often a
    truncated or rejected candidate config (`failed_candidatecfg.xml`).

    A config that fails ``ET.parse`` used to register *nothing*, so its
    identifiers went out un-anonymized — invisible to the compare mode, which
    only knows the mapping. The pull parser yields every element up to the
    error with its parent context intact, so the vendor-catalog guardrails
    (_SKIP_SUBTREES, <config><global>, _is_vocabulary) still apply — a bare
    regex sweep over ``<entry name=…>`` would have re-registered the 41 973
    App-ID names the tree walk exists to skip.
    """
    parser = ET.XMLPullParser(events=("start", "end"))
    stack: list[str] = []
    skip_depth = 0
    try:
        with open(xml_path, "rb") as f:
            while True:
                chunk = f.read(1 << 20)
                stop = not chunk
                try:
                    if chunk:
                        parser.feed(chunk)
                    else:
                        parser.close()  # raises on a truncated document
                except ET.ParseError:
                    stop = True
                for event, elem in parser.read_events():
                    tag = elem.tag.split("}")[-1] if "}" in elem.tag else elem.tag
                    if event == "start":
                        parent = stack[-1] if stack else ""
                        stack.append(tag)
                        if skip_depth:
                            skip_depth += 1
                        elif tag in _SKIP_SUBTREES or (tag == "global" and parent == "config"):
                            skip_depth = 1
                        elif tag == "entry":
                            _register_entry_name(elem.get("name"), parent, anon)
                    else:
                        if stack:
                            stack.pop()
                        if skip_depth:
                            skip_depth -= 1
                        elif elem.text and elem.text.strip():
                            _register_sensitive_field(tag, elem.text.strip(), anon)
                if stop:
                    break
    except Exception as e:  # salvage is best-effort by definition
        logger.warning("prescan: salvage of %s stopped early: %s", xml_path.name, e)


def prescan_config_xml(xml_path: Path, anon: Anonymizer) -> tuple[int, int]:
    """Returns (objects added, fqdns added)."""
    before = len(anon.named_obj_map)
    before_fqdn = len(anon.fqdn_map)
    try:
        tree = ET.parse(xml_path)
        _walk_xml(tree.getroot(), anon)
    except ET.ParseError as e:
        logger.warning("prescan: could not parse %s (%s) — salvaging the parseable prefix",
                       xml_path.name, e)
        _salvage_prescan_xml(xml_path, anon)
    return len(anon.named_obj_map) - before, len(anon.fqdn_map) - before_fqdn


# ---------------------------------------------------------------------------
# File processing
# ---------------------------------------------------------------------------

# What a redacted binary member is replaced with. A stable, recognizable
# sentinel: the compare identifies a deliberate redaction by these exact
# bytes and then verifies it was warranted against the original.
REDACTED_PAYLOAD = (
    b"[tsf-anonymizer] binary payload redacted: "
    b"the original embedded identifiers from the mapping.\n"
)


@dataclass
class FileOutcome:
    path: str
    action: str  # modified | unchanged | binary | gz_binary | redacted | error
    replacements: dict[str, int] = field(default_factory=dict)
    error: Optional[str] = None
    # Identifiers the frozen rewrite would have had to allocate a pseudonym
    # for — the detection prescan should make this impossible, so anything
    # here is a bug to surface, not to hide.
    warnings: list[str] = field(default_factory=list)


def _decode(raw: bytes) -> str:
    return raw.decode("utf-8", errors="surrogateescape")


def _encode(text: str) -> bytes:
    return text.encode("utf-8", errors="surrogateescape")


def anonymize_bytes(raw: bytes, anon: Anonymizer) -> Optional[bytes]:
    """Anonymize a text payload. Returns None when nothing changed."""
    original = _decode(raw)
    anonymized = anon.anonymize_text(original)
    if anonymized == original:
        return None
    return _encode(anonymized)


def process_file(path: Path, anon: Anonymizer, rel: str = "") -> FileOutcome:
    rel = rel or str(path)
    # .gz first: compressed bytes are binary, the content usually is not.
    if path.suffix == ".gz":
        return process_gz_file(path, anon, rel)

    if is_binary_file(path):
        if anon.redact_binaries:
            try:
                if anon.binary_embeds_identifier(path.read_bytes()):
                    path.write_bytes(REDACTED_PAYLOAD)
                    return FileOutcome(rel, "redacted")
            except Exception as e:
                logger.warning("redaction scan failed on %s: %s", rel, e)
        return FileOutcome(rel, "binary")

    try:
        misses_before = set(anon.frozen_misses)
        raw = path.read_bytes()
        out = anonymize_bytes(raw, anon)
        warnings = _new_frozen_misses(anon, misses_before, rel)
        if out is None:
            return FileOutcome(rel, "unchanged", warnings=warnings)
        path.write_bytes(out)
        return FileOutcome(rel, "modified", dict(anon.last_counts), warnings=warnings)
    except Exception as e:  # pragma: no cover - defensive
        logger.warning("skipping %s: %s", rel, e)
        return FileOutcome(rel, "error", error=str(e))


def _new_frozen_misses(anon: Anonymizer, before: set[str], rel: str) -> list[str]:
    # Logged by _tally in the parent, where a worker process's records reach
    # the job's own captured log.
    return sorted(anon.frozen_misses - before)[:50]


def process_gz_file(path: Path, anon: Anonymizer, rel: str = "") -> FileOutcome:
    rel = rel or str(path)
    try:
        misses_before = set(anon.frozen_misses)
        with gzip.open(path, "rb") as f:
            raw = f.read()
        if is_binary_bytes(raw[:4096]):
            if anon.redact_binaries and anon.binary_embeds_identifier(raw):
                # mtime=0 keeps the redacted member byte-identical whatever
                # worker (or run) produced it.
                with open(path, "wb") as out:
                    with gzip.GzipFile(fileobj=out, mode="wb", mtime=0) as gz:
                        gz.write(REDACTED_PAYLOAD)
                return FileOutcome(rel, "redacted")
            return FileOutcome(rel, "gz_binary")
        out = anonymize_bytes(raw, anon)
        warnings = _new_frozen_misses(anon, misses_before, rel)
        if out is None:
            return FileOutcome(rel, "unchanged", warnings=warnings)
        # Level 6, not the gzip default of 9: measured 12 MB/s at 9 against
        # 38 MB/s at 6 for the same output size on this kind of text — the
        # same trade the outer repack already makes.
        with gzip.open(path, "wb", compresslevel=6) as f:
            f.write(out)
        return FileOutcome(rel, "modified", dict(anon.last_counts), warnings=warnings)
    except Exception as e:
        logger.warning("skipping gz %s: %s", rel, e)
        return FileOutcome(rel, "error", error=str(e))


# ---------------------------------------------------------------------------
# Archive handling
# ---------------------------------------------------------------------------

MAX_FILES = 200_000
MAX_UNCOMPRESSED_BYTES = 8 * 1024 * 1024 * 1024


def _is_safe_member(member: tarfile.TarInfo, work_dir: Path) -> bool:
    if member.issym() or member.islnk():
        return False
    if not (member.isfile() or member.isdir()):
        return False
    parts = Path(member.name).parts
    if any(p == ".." for p in parts):
        return False
    try:
        (work_dir / member.name).resolve().relative_to(work_dir.resolve())
    except (ValueError, OSError):
        return False
    return True


def extract_archive(archive: Path, work_dir: Path, *,
                    progress: ProgressFn = _noop_progress,
                    phase: str = "extract") -> tuple[list[tarfile.TarInfo], int]:
    """Extract safely. Returns (members in archive order, members skipped).

    The returned TarInfo objects carry the archive's *original* metadata —
    repack_archive reads them back. What is written to disk gets u+rw (files)
    / u+rwx (dirs) added, because a real TSF ships files in mode 0000 and the
    working copy has to be readable and writable; that widening must never
    reach the output archive.

    The extraction is driven in slices so it can say how far it is: on a real
    TSF this phase is minutes long, and a bar that only knows "started" and
    "finished" cannot be told from a hung run. Slices keep `extractall`'s own
    semantics (directory attributes applied after their contents) and read the
    stream forward-only, which is what keeps a gzip member cheap to reach.
    """
    work_dir.mkdir(parents=True, exist_ok=True)
    members: list[tarfile.TarInfo] = []
    to_extract: list[tarfile.TarInfo] = []
    skipped = 0
    total = 0
    with tarfile.open(archive, "r:*") as tar:
        for m in tar.getmembers():
            m.name = m.name.lstrip("/")
            if not m.name or m.name == ".":
                m.name = "."
            if m.name != "." and not _is_safe_member(m, work_dir):
                skipped += 1
                continue
            if len(members) >= MAX_FILES:
                raise ValueError(f"archive has more than {MAX_FILES} members")
            if m.isfile():
                total += m.size
                if total > MAX_UNCOMPRESSED_BYTES:
                    raise ValueError("archive uncompressed size exceeds the safety cap")
            members.append(m)
            if m.name == ".":
                continue
            disk = copy.copy(m)
            disk.mode |= 0o600 if m.isfile() else 0o700
            to_extract.append(disk)
        total = len(to_extract)
        progress(phase, 0, total, f"Extracting {archive.name}")
        step = max(1, total // 200)
        for i in range(0, total, step):
            chunk = to_extract[i:i + step]
            tar.extractall(work_dir, members=chunk)
            progress(phase, min(i + step, total), total, archive.name)
    return members, skipped


def repack_archive(members: Iterable[tarfile.TarInfo], tree: Path, output: Path, *,
                   progress: ProgressFn = _noop_progress,
                   rename: Optional[Callable[[str], str]] = None) -> int:
    """Write `output` with the same member order and metadata as the input,
    swapping in the payload found under `tree`. Returns members written.

    `rename` maps a member name to the name it gets in the output — member
    names carry identifiers too (techsupport_<devicename>_<date>.txt). The
    payload is still read under the *original* name on disk."""
    members = list(members)
    total, written = len(members), 0
    # ~100 updates whatever the size: a small archive still moves, a 500-member
    # one does not write job.json for every file.
    step = max(1, total // 100)
    # Level 6, not gzip's 9: measured on a real TSF, 9 runs at 61 MB/s and 6 at
    # 133 MB/s for the *same* output size — the last three levels buy nothing
    # on this kind of text and cost half the repack phase.
    with tarfile.open(output, "w:gz", compresslevel=6) as tar:
        for m in members:
            if written % step == 0:
                progress("repack", written, total, output.name)
            if m.name == ".":
                continue
            info = tarfile.TarInfo(rename(m.name) if rename else m.name)
            info.mode, info.uid, info.gid = m.mode, m.uid, m.gid
            info.uname, info.gname, info.mtime = m.uname, m.gname, m.mtime
            info.type = m.type
            src = tree / m.name
            if m.isdir():
                tar.addfile(info)
            elif m.isfile():
                info.size = src.stat().st_size
                with open(src, "rb") as f:
                    tar.addfile(info, f)
            written += 1
    progress("repack", total, total, output.name)
    return written


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

CONFIG_GLOBS = (
    "running-config.xml", "candidate-config.xml", "*.xml",
)


@dataclass
class AnonymizeReport:
    input_name: str
    output_name: Optional[str]
    files_total: int = 0
    modified: int = 0
    unchanged: int = 0
    binary: int = 0
    redacted: int = 0
    errors: int = 0
    members_skipped: int = 0
    members_renamed: int = 0
    config_files_scanned: int = 0
    mapping_sizes: dict[str, int] = field(default_factory=dict)
    replacements: dict[str, int] = field(default_factory=dict)
    files: list[FileOutcome] = field(default_factory=list)
    duration_s: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


# Whole files that are vendor content, never customer configuration.
_PRESCAN_SKIP_NAMES = {"predefined.xml", "global.xml", "reg_ips.xml", "sysd_objects_meta.xml"}
_PRESCAN_SKIP_PARTS = {"updates", "regip", "healthchecks"}


def _is_prescan_candidate(p: Path) -> bool:
    if not p.is_file() or p.name in _PRESCAN_SKIP_NAMES:
        return False
    if "reportconfig" in p.name or "info" in p.name and p.name.startswith((".", "av", "content")):
        return False
    return not (set(p.parts) & _PRESCAN_SKIP_PARTS)


# tmp/cli/techsupport_<devicename>_<YYYYMMDD>_<HHMM>.txt — the device's own
# name, chosen by the customer, in a member name. Not the model (the skill
# used to say so): verified on four real TSFs.
_TECHSUPPORT_NAME_RE = re.compile(r"^techsupport_(.+)_(\d{8})_(\d{4})\.txt$")
_MODEL_LIKE_RE = re.compile(r"^(?:PA|VM|M|PAN|WF|CN)-?\d", re.IGNORECASE)
_SYSINFO_KEYS = {"hostname": "host", "devicename": "host", "domain": "host", "serial": "serial"}


def _prescan_system_info(tree: Path, anon: Anonymizer) -> int:
    """The device's identity as the device itself states it: the name in the
    techsupport txt file name and the `> show system info` block. Authoritative
    — no "looks like a device name" heuristic here: a hostname without a digit
    or hyphen (`CoreFirewall`) went out in clear on three of four real TSFs,
    in a member name and in the text."""
    found = 0
    for ts in sorted((tree / "tmp" / "cli").glob("techsupport_*.txt")):
        m = _TECHSUPPORT_NAME_RE.match(ts.name)
        if m and not _MODEL_LIKE_RE.match(m.group(1)) and m.group(1).lower() not in BUILTIN_OBJECTS:
            anon.register_fqdn(m.group(1))
            found += 1
        try:
            head = ts.read_bytes()[:2_000_000].decode("utf-8", "surrogateescape")
        except Exception:
            continue
        block = re.search(r"^> show system info.*?(?=^> |\Z)", head, re.S | re.M)
        if not block:
            continue
        for key, kind in _SYSINFO_KEYS.items():
            mm = re.search(rf"^{key}:\s*(\S+)\s*$", block.group(0), re.M)
            if not mm:
                continue
            val = mm.group(1).strip()
            if kind == "host":
                if (len(val) > 2 and val.lower() not in BUILTIN_OBJECTS
                        and not _IP_LIKE_RE.match(val) and not _MODEL_LIKE_RE.match(val)
                        and val.lower() not in ("unknown", "none")):
                    anon.register_fqdn(val)
                    found += 1
            elif kind == "serial" and val.isdigit() and 8 <= len(val) <= 16:
                anon.anon_serial(val)
                found += 1
    return found


def prescan_tree(tree: Path, anon: Anonymizer, progress: ProgressFn = _noop_progress) -> int:
    """Prescan every customer-config XML in the tree. Running/candidate configs
    first so they own the categories; other XMLs then only add what they
    introduce. Vendor content (App-ID catalog, URL DB, report templates) is
    skipped — see _is_prescan_candidate / _SKIP_SUBTREES."""
    _prescan_system_info(tree, anon)
    primary = sorted(tree.rglob("running-config.xml")) + sorted(tree.rglob("candidate-config.xml"))
    seen = set(primary)
    others = [p for p in sorted(tree.rglob("*.xml")) if p not in seen and _is_prescan_candidate(p)]
    files = primary + others
    for i, cfg in enumerate(files, 1):
        if cfg.stat().st_size > 200 * 1024 * 1024:
            continue
        added_obj, added_fqdn = prescan_config_xml(cfg, anon)
        progress("prescan", i, len(files),
                 f"{cfg.name}: +{added_obj} objects, +{added_fqdn} FQDNs")
    return len(files)


# "hostname Tab-S6-Lite-de-Thomas, interface ethernet1/8.100" (pan_dhcpd.log),
# "hostname: fw01", 'hostname="x"'. A device named after its owner is PII
# that no config declares. `hostname=?` (audit.log) does not match.
# Two exact shapes only. The first cut used `hostname\s*(\S+)`: `\s*` crosses
# a newline, so a *file* named "hostname" in an ls listing captured the next
# line's first word (drwxr-xr-x, 252.acl), and prose ("hostname to …")
# registered "to", "of", "in" as FQDNs — 2.3 M lines rewritten, <equal-to>
# tags included. The value must also look like a device name (a digit, a
# hyphen or a dot), so "iphone" alone is not one.
_HOSTNAME_PHRASE_RE = re.compile(
    r"(?:\bhostname[:=][ \t]*[\"']?|\bhostname[ \t]+)"
    r"([A-Za-z][A-Za-z0-9._-]{2,62})(?=[\"',;\s]|$)"
)


def _looks_like_device_name(value: str) -> bool:
    return (any(c.isdigit() or c in ".-" for c in value)
            and not _FILE_SUFFIX_RE.search(value) and not _IP_LIKE_RE.match(value))


_FILE_SUFFIX_RE = re.compile(
    r"\.(?:gz|log|xml|txt|json|js|css|png|jpg|pem|crt|csr|key|pcap|tar|tgz|zip|"
    r"service|socket|journal|yang|stats|cfg|acl|conf|d|ha|\d+)$", re.IGNORECASE
)


def _detect_in_file(path) -> list[tuple]:
    """Every identity one text file reveals, in position order per kind:
    usernames (log phrasings), e-mails, `hostname X` phrases — and IPs and
    fallback-shaped serials, so that *nothing* is left to discover at rewrite
    time and the tables can be frozen. Pure and stateless (the detection
    regexes need no tables), which is what lets it run in worker processes;
    allocation stays in the parent, in path order, so the pseudonym counters
    fall exactly as a sequential run's would."""
    path = Path(path)
    try:
        if path.suffix == ".gz":
            with gzip.open(path, "rb") as f:
                raw = f.read()
            if is_binary_bytes(raw[:4096]):
                return []
        elif is_binary_file(path):
            return []
        else:
            raw = path.read_bytes()
    except Exception:
        return []
    text = _decode(raw)
    found: dict[tuple, None] = {}
    for m in _USER_PHRASE_RE.finditer(text):
        found.setdefault(("user", m.group(1)))
    for m in _EMAIL_RE.finditer(text):
        found.setdefault(("email", m.group(1), m.group(2)))
    for m in _HOSTNAME_PHRASE_RE.finditer(text):
        if _looks_like_device_name(m.group(1)):
            found.setdefault(("host", m.group(1)))
    for m in _IP_RE.finditer(text):
        if _valid_ipv4_octets(m.group(1)):
            found.setdefault(("ip", m.group(1)))
    for m in _SERIAL_FALLBACK_RE.finditer(text):
        found.setdefault(("serial", m.group(1)))
    return list(found)


def _register_findings(anon: Anonymizer, findings: list[tuple]) -> int:
    """Apply one file's detections. Returns how many usernames were new."""
    users = 0
    for f in findings:
        kind = f[0]
        if kind == "user":
            if anon.anon_user(f[1]) != f[1]:
                users += 1
        elif kind == "email":
            anon.anon_email(f[1], f[2])
        elif kind == "host":
            anon.register_fqdn(f[1])
        elif kind == "ip":
            anon.anon_ip(f[1])
        elif kind == "serial":
            anon.anon_serial(f[1])
    return users


def prescan_text_identities(tree: Path, anon: Anonymizer,
                            progress: ProgressFn = _noop_progress,
                            workers: int = 1) -> int:
    """Discover every text-borne identity — usernames, e-mails, hostnames,
    IPs, fallback serials — before anything is rewritten, so the first file
    sees the same tables as the last, every occurrence is replaced, and the
    tables can then be frozen (which is what makes the rewrite itself safe
    to spread over processes). Detection is read-only and stateless, so
    `workers` > 1 fans the file scans out; registration always happens here,
    in path order, keeping "same original → same pseudonym" scheduling-free."""
    paths = [p for p in sorted(tree.rglob("*")) if p.is_file()]
    found = 0

    def _apply(i: int, findings: list[tuple]) -> None:
        nonlocal found
        found += _register_findings(anon, findings)
        if i % 25 == 0 or i == len(paths):
            progress("prescan-text", i, len(paths),
                     f"{len(anon.user_map)} users, {len(anon.email_map)} e-mails, "
                     f"{len(anon.ip_map)} IPs")

    if workers > 1 and len(paths) > 1:
        # forkserver, not fork: this runs on a worker thread of a live server,
        # and forking a threaded process inherits locks held by other threads.
        ctx = multiprocessing.get_context("forkserver")
        with ProcessPoolExecutor(max_workers=workers, mp_context=ctx) as pool:
            for i, findings in enumerate(
                    pool.map(_detect_in_file, map(str, paths), chunksize=1), 1):
                _apply(i, findings)
    else:
        for i, p in enumerate(paths, 1):
            _apply(i, _detect_in_file(p))
    return found


# One frozen Anonymizer per rewrite worker, built by the initializer:
# compiling the tries over the full mapping is the expensive part, and it
# must be paid once per worker, not once per file.
_REWRITE_STATE: tuple[Anonymizer, Path] | None = None


def _init_rewrite_worker(mapping: dict, tree: str, redact_binaries: bool) -> None:
    global _REWRITE_STATE
    worker_anon = Anonymizer.from_mapping(mapping)
    worker_anon.frozen = True
    worker_anon.redact_binaries = redact_binaries
    _REWRITE_STATE = (worker_anon, Path(tree))


def _process_in_worker(rel: str) -> FileOutcome:
    worker_anon, tree = _REWRITE_STATE
    try:
        return process_file(tree / rel, worker_anon, rel)
    except Exception as e:  # a worker crash must cost one file, not the run
        return FileOutcome(rel, "error", error=f"rewrite worker failed: {e}")


def _tally(report: AnonymizeReport, outcome: FileOutcome) -> None:
    report.files.append(outcome)
    if outcome.warnings:
        logger.warning("%s: frozen rewrite left %d undetected identifier(s) unreplaced: %s",
                       outcome.path, len(outcome.warnings), outcome.warnings[:10])
    if outcome.action == "modified":
        report.modified += 1
        for k, v in outcome.replacements.items():
            report.replacements[k] = report.replacements.get(k, 0) + v
    elif outcome.action == "unchanged":
        report.unchanged += 1
    elif outcome.action in ("binary", "gz_binary"):
        report.binary += 1
    elif outcome.action == "redacted":
        report.redacted += 1
    else:
        report.errors += 1
        if outcome.error:
            logger.warning("%s: %s", outcome.path, outcome.error)


def anonymize_tree(tree: Path, anon: Anonymizer, report: AnonymizeReport,
                   progress: ProgressFn = _noop_progress, workers: int = 1) -> None:
    """Rewrite every file under `tree`. With the tables frozen the rewrite is
    a pure lookup, so `workers` > 1 spreads it over processes — outcomes are
    collected back in path order and the result does not depend on scheduling.
    The un-frozen sequential path is kept for direct API use."""
    paths = [p for p in sorted(tree.rglob("*")) if p.is_file()]
    report.files_total = len(paths)
    if workers > 1 and len(paths) > 1 and anon.frozen:
        rels = [str(p.relative_to(tree)) for p in paths]
        ctx = multiprocessing.get_context("forkserver")
        with ProcessPoolExecutor(max_workers=workers, mp_context=ctx,
                                 initializer=_init_rewrite_worker,
                                 initargs=(anon.get_mapping(), str(tree),
                                           anon.redact_binaries)) as pool:
            for i, outcome in enumerate(pool.map(_process_in_worker, rels, chunksize=1), 1):
                _tally(report, outcome)
                if i % 25 == 0 or i == len(paths):
                    progress("anonymize", i, len(paths), outcome.path)
    else:
        for i, p in enumerate(paths, 1):
            rel = str(p.relative_to(tree))
            _tally(report, process_file(p, anon, rel))
            if i % 25 == 0 or i == len(paths):
                progress("anonymize", i, len(paths), rel)
    report.mapping_sizes = {k: len(v) for k, v in anon.get_mapping().items()}


def anonymize_tsf(
    input_tgz: Path,
    output_tgz: Optional[Path],
    mapping_only: bool = False,
    seed_mapping: Optional[dict] = None,
    work_root: Optional[Path] = None,
    keep_trees: bool = False,
    progress: ProgressFn = _noop_progress,
    workers: int = 1,
    redact_binaries: bool = False,
) -> tuple[AnonymizeReport, dict]:
    """Anonymize an archive.

    With ``work_root`` and ``keep_trees=True`` the original tree stays at
    ``work_root/orig`` and the anonymized one at ``work_root/anon`` so the
    compare mode can run over them without re-extracting.

    ``workers`` > 1 spreads the text prescan and the rewrite over processes.
    The mapping and the output are the same whatever the count: detection
    feeds allocation in path order, and the rewrite runs with frozen tables.
    """
    import shutil

    t0 = time.monotonic()
    anon = Anonymizer.from_mapping(seed_mapping) if seed_mapping else Anonymizer()
    report = AnonymizeReport(input_name=input_tgz.name,
                             output_name=output_tgz.name if output_tgz else None)

    tmp_ctx = tempfile.TemporaryDirectory(prefix="tsf_anon_") if work_root is None else None
    root = Path(tmp_ctx.name) if tmp_ctx else work_root
    root.mkdir(parents=True, exist_ok=True)
    try:
        orig_dir = root / "orig"
        anon_dir = root / "anon"

        # Reading the member list decompresses the whole archive once, before a
        # single file is written: it is part of the wait, so it says so.
        progress("extract", 0, 1, f"Reading {input_tgz.name}")
        members, skipped = extract_archive(input_tgz, orig_dir, progress=progress)
        report.members_skipped = skipped

        files = sum(1 for m in members if m.isfile())
        progress("copy", 0, files, "Preparing working copy")
        if anon_dir.exists():
            shutil.rmtree(anon_dir)
        copied, step = [0], max(1, files // 100)

        def _copy_one(src, dst):
            shutil.copy2(src, dst)
            copied[0] += 1
            if copied[0] % step == 0:
                progress("copy", copied[0], files, "")

        # copytree still creates the tree; the hook only counts the payloads it
        # writes, which is where the ~1.5 GB of a real TSF goes.
        shutil.copytree(orig_dir, anon_dir, symlinks=False, copy_function=_copy_one)
        progress("copy", files, files, "")

        report.config_files_scanned = prescan_tree(anon_dir, anon, progress)
        prescan_text_identities(anon_dir, anon, progress, workers=workers)
        anon.build_patterns()
        # Every identity is now on the table; freeze them so the rewrite is a
        # pure lookup — allocation during the rewrite would make the mapping
        # depend on scheduling, which is the one thing it must never do.
        anon.frozen = True
        anon.redact_binaries = redact_binaries

        if mapping_only:
            report.duration_s = time.monotonic() - t0
            return report, anon.get_mapping()

        anonymize_tree(anon_dir, anon, report, progress, workers=workers)

        if output_tgz is not None:
            progress("repack", 0, len(members), f"Repacking → {output_tgz.name}")
            output_tgz.parent.mkdir(parents=True, exist_ok=True)
            renamed = [0]

            def _rename(name: str) -> str:
                # Same frozen tables, same passes: a member name is text too.
                new = anon.anonymize_text(name)
                if new != name:
                    renamed[0] += 1
                return new

            repack_archive(members, anon_dir, output_tgz, progress=progress, rename=_rename)
            report.members_renamed = renamed[0]
            mapping_path = mapping_sidecar_path(output_tgz)
            mapping_path.write_text(
                json.dumps(anon.get_mapping(), indent=2, ensure_ascii=False), encoding="utf-8"
            )
            progress("repack", len(members), len(members), "")

        if not keep_trees and work_root is not None:
            shutil.rmtree(orig_dir, ignore_errors=True)
            shutil.rmtree(anon_dir, ignore_errors=True)
    finally:
        if tmp_ctx:
            tmp_ctx.cleanup()

    report.duration_s = time.monotonic() - t0
    return report, anon.get_mapping()


def mapping_sidecar_path(output_tgz: Path) -> Path:
    name = output_tgz.name
    for suf in (".tar.gz", ".tgz", ".tar"):
        if name.endswith(suf):
            name = name[: -len(suf)]
            break
    return output_tgz.with_name(name + ".mapping.json")


def default_output_path(input_path: Path) -> Path:
    name = input_path.name
    for suf in (".tar.gz", ".tgz", ".tar"):
        if name.endswith(suf):
            name = name[: -len(suf)]
            break
    return input_path.parent / f"{name}_anon.tgz"
