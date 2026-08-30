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
import re
import tarfile
import tempfile
import time
import xml.etree.ElementTree as ET
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

BINARY_EXTENSIONS = {
    ".bin", ".dat", ".ebl", ".db", ".sqlite", ".png", ".jpg", ".jpeg",
    ".gif", ".ico", ".pdf", ".zip", ".tar", ".rpm", ".deb", ".so", ".a",
    ".pyc", ".pyo", ".whl", ".egg", ".core", ".pcap", ".cap",
}


def is_binary_bytes(chunk: bytes) -> bool:
    if b"\x00" in chunk:
        return True
    if not chunk:
        return False
    non_text = sum(1 for b in chunk if b < 9 or (13 < b < 32) or b == 127)
    return non_text / len(chunk) > 0.30


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

        # Not preceded by a digit or dot, not followed by a digit or by
        # ".<digit>" — so 10.1.2.3.4 is not half-rewritten, but "peer 10.0.0.5."
        # at the end of a sentence is.
        self._ip_re = re.compile(
            r"(?<![.\d])(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(/\d{1,2})?(?!\d)(?!\.\d)"
        )
        self._user_re = re.compile(
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
        self._serial_re = re.compile(
            r"(?<!\d)(?!(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])(?:[01]\d|2[0-3])[0-5]\d(?:19|20)\d\d(?!\d))"
            r"(0(?!000)\d{11}|007\d{12})(?!\d)"
        )
        self._email_re = re.compile(
            r"\b([a-zA-Z0-9._%+\-]+)@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b"
        )

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
        if (username.lower() in BUILTIN_OBJECTS or username in self._fakes
                or username.startswith(_VOCAB_PREFIXES)):
            return username
        if username not in self.user_map:
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
        self.anon_fqdn(fqdn)

    # -- Email anonymization ------------------------------------------------

    def anon_email(self, local: str, domain: str) -> str:
        original = f"{local}@{domain}"
        if original in self.email_map:
            return self.email_map[original]
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
        if self.named_obj_map:
            # A name is replaced only as a whole token: not inside a longer
            # word, not as one segment of a hyphenated compound ("web" in
            # "web-server-1"), not as a label of a dotted name on the left
            # ("x.Zone-A"). A dot *after* is fine — sentence ends.
            # "<" and "</" excluded before, "=" and "://" after: an object named
            # like an XML tag, an attribute or a URL scheme must not rewrite
            # <enabled>, name="…" or http://. Verified on a real TSF: it did.
            self._obj_re = re.compile(
                r"(?<![\w.\-<])(?<!<\/)" + trie_regex(self.named_obj_map) + r"(?![\w\-=])(?!:\/\/)"
            )
        else:
            self._obj_re = None
        if self.fqdn_map:
            # "/" before is allowed on purpose: https://vpn.acme.fr/ and
            # /path/to/vpn.acme.fr.csr must be rewritten; only </tag> is not.
            # "." after is allowed too — a sentence ends, a file has a suffix.
            self._fqdn_re = re.compile(
                r"(?<![.\w<])(?<!<\/)" + trie_regex(self.fqdn_map) + r"(?![\w\-=])(?!:\/\/)",
                re.IGNORECASE,
            )
        else:
            self._fqdn_re = None
        # Usernames (from the config's <users>/<admin> entries they are named
        # objects; from log phrasings they land here) are replaced wherever they
        # appear — UID="x", (x), x@host — not only in the phrasing that found them.
        self._user_trie_re = (
            re.compile(r"(?<![\w.\-<@])(?<!<\/)" + trie_regex(self.user_map) + r"(?![\w\-=])(?!:\/\/)")
            if self.user_map else None
        )
        self._built_for = self._map_sizes()
        # Serials discovered in the config are replaced wherever they appear,
        # whatever their shape; the regex fallback below is stricter.
        self._known_serial_re = (
            re.compile(r"(?<!\d)" + trie_regex(self.serial_map) + r"(?!\d)")
            if self.serial_map else None
        )

    def _map_sizes(self) -> tuple:
        return (len(self.named_obj_map), len(self.fqdn_map), len(self.user_map),
                len(self.serial_map))

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
        if self._user_trie_re is not None:
            table = self.user_map

            def sub_known(m: re.Match) -> str:
                self._count("usernames")
                return table[m.group(0)]
            text = self._user_trie_re.sub(sub_known, text)

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
        if self._obj_re is None:
            return text
        table = self.named_obj_map

        def replace_match(m: re.Match) -> str:
            fake = table.get(m.group(0))
            if fake is None:
                return m.group(0)
            self._count("named_objects")
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
        anon.email_map.update(mapping.get("emails", {}))
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
_EMAIL_IN_TEXT_RE = re.compile(r"\b([a-zA-Z0-9._%+\-]+)@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})\b")
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
        name_attr = elem.get("name")
        if (name_attr and len(name_attr) >= 2 and name_attr.lower() not in BUILTIN_OBJECTS
                and not _is_vocabulary(name_attr, parent_tag)):
            name_attr = name_attr.strip()
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

    field_type = SENSITIVE_XML_FIELDS.get(tag)
    if field_type and elem.text and elem.text.strip():
        val = elem.text.strip()
        if field_type == "fqdn":
            if "." in val and not val.startswith("DC=") and not _IPV4_ONLY_RE.match(val):
                anon.register_fqdn(val)
        elif field_type == "host":
            if len(val) > 2 and val.lower() not in BUILTIN_OBJECTS and not _IPV4_ONLY_RE.match(val):
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

    for child in elem:
        _walk_xml(child, anon, parent_tag=tag)


def prescan_config_xml(xml_path: Path, anon: Anonymizer) -> tuple[int, int]:
    """Returns (objects added, fqdns added)."""
    before = len(anon.named_obj_map)
    before_fqdn = len(anon.fqdn_map)
    try:
        tree = ET.parse(xml_path)
        _walk_xml(tree.getroot(), anon)
    except ET.ParseError as e:
        logger.warning("prescan: could not parse %s: %s", xml_path.name, e)
    return len(anon.named_obj_map) - before, len(anon.fqdn_map) - before_fqdn


# ---------------------------------------------------------------------------
# File processing
# ---------------------------------------------------------------------------

@dataclass
class FileOutcome:
    path: str
    action: str  # modified | unchanged | binary | gz_binary | error
    replacements: dict[str, int] = field(default_factory=dict)
    error: Optional[str] = None


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
        return FileOutcome(rel, "binary")

    try:
        raw = path.read_bytes()
        out = anonymize_bytes(raw, anon)
        if out is None:
            return FileOutcome(rel, "unchanged")
        path.write_bytes(out)
        return FileOutcome(rel, "modified", dict(anon.last_counts))
    except Exception as e:  # pragma: no cover - defensive
        logger.warning("skipping %s: %s", rel, e)
        return FileOutcome(rel, "error", error=str(e))


def process_gz_file(path: Path, anon: Anonymizer, rel: str = "") -> FileOutcome:
    rel = rel or str(path)
    try:
        with gzip.open(path, "rb") as f:
            raw = f.read()
        if is_binary_bytes(raw[:4096]):
            return FileOutcome(rel, "gz_binary")
        out = anonymize_bytes(raw, anon)
        if out is None:
            return FileOutcome(rel, "unchanged")
        with gzip.open(path, "wb") as f:
            f.write(out)
        return FileOutcome(rel, "modified", dict(anon.last_counts))
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


def extract_archive(archive: Path, work_dir: Path) -> tuple[list[tarfile.TarInfo], int]:
    """Extract safely. Returns (members in archive order, members skipped).

    The returned TarInfo objects carry the archive's *original* metadata —
    repack_archive reads them back. What is written to disk gets u+rw (files)
    / u+rwx (dirs) added, because a real TSF ships files in mode 0000 and the
    working copy has to be readable and writable; that widening must never
    reach the output archive.
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
        tar.extractall(work_dir, members=to_extract)
    return members, skipped


def repack_archive(members: Iterable[tarfile.TarInfo], tree: Path, output: Path) -> int:
    """Write `output` with the same member order and metadata as the input,
    swapping in the payload found under `tree`. Returns members written."""
    written = 0
    with tarfile.open(output, "w:gz") as tar:
        for m in members:
            if m.name == ".":
                continue
            info = tarfile.TarInfo(m.name)
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
    errors: int = 0
    members_skipped: int = 0
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


def prescan_tree(tree: Path, anon: Anonymizer, progress: ProgressFn = _noop_progress) -> int:
    """Prescan every customer-config XML in the tree. Running/candidate configs
    first so they own the categories; other XMLs then only add what they
    introduce. Vendor content (App-ID catalog, URL DB, report templates) is
    skipped — see _is_prescan_candidate / _SKIP_SUBTREES."""
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


def prescan_text_identities(tree: Path, anon: Anonymizer,
                            progress: ProgressFn = _noop_progress) -> int:
    """Discover usernames (log phrasings) and e-mails in every text file before
    anything is rewritten, so the first file sees the same tables as the last
    and every occurrence — not only the phrasing that revealed it — is replaced.
    One extra read of the corpus; the regexes run in C."""
    paths = [p for p in sorted(tree.rglob("*")) if p.is_file()]
    found = 0
    for i, p in enumerate(paths, 1):
        try:
            if p.suffix == ".gz":
                with gzip.open(p, "rb") as f:
                    raw = f.read()
                if is_binary_bytes(raw[:4096]):
                    continue
            elif is_binary_file(p):
                continue
            else:
                raw = p.read_bytes()
        except Exception:
            continue
        text = _decode(raw)
        for m in anon._user_re.finditer(text):
            if anon.anon_user(m.group(1)) != m.group(1):
                found += 1
        for m in anon._email_re.finditer(text):
            anon.anon_email(m.group(1), m.group(2))
        if i % 25 == 0 or i == len(paths):
            progress("prescan-text", i, len(paths), f"{len(anon.user_map)} users, {len(anon.email_map)} e-mails")
    return found


def anonymize_tree(tree: Path, anon: Anonymizer, report: AnonymizeReport,
                   progress: ProgressFn = _noop_progress) -> None:
    paths = [p for p in sorted(tree.rglob("*")) if p.is_file()]
    report.files_total = len(paths)
    for i, p in enumerate(paths, 1):
        rel = str(p.relative_to(tree))
        outcome = process_file(p, anon, rel)
        report.files.append(outcome)
        if outcome.action == "modified":
            report.modified += 1
            for k, v in outcome.replacements.items():
                report.replacements[k] = report.replacements.get(k, 0) + v
        elif outcome.action == "unchanged":
            report.unchanged += 1
        elif outcome.action in ("binary", "gz_binary"):
            report.binary += 1
        else:
            report.errors += 1
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
) -> tuple[AnonymizeReport, dict]:
    """Anonymize an archive.

    With ``work_root`` and ``keep_trees=True`` the original tree stays at
    ``work_root/orig`` and the anonymized one at ``work_root/anon`` so the
    compare mode can run over them without re-extracting.
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

        progress("extract", 0, 1, f"Extracting {input_tgz.name}")
        members, skipped = extract_archive(input_tgz, orig_dir)
        report.members_skipped = skipped
        progress("extract", 1, 1, f"{len(members)} members")

        progress("copy", 0, 1, "Preparing working copy")
        if anon_dir.exists():
            shutil.rmtree(anon_dir)
        shutil.copytree(orig_dir, anon_dir, symlinks=False)
        progress("copy", 1, 1, "")

        report.config_files_scanned = prescan_tree(anon_dir, anon, progress)
        prescan_text_identities(anon_dir, anon, progress)
        anon.build_patterns()

        if mapping_only:
            report.duration_s = time.monotonic() - t0
            return report, anon.get_mapping()

        anonymize_tree(anon_dir, anon, report, progress)

        if output_tgz is not None:
            progress("repack", 0, 1, f"Repacking → {output_tgz.name}")
            output_tgz.parent.mkdir(parents=True, exist_ok=True)
            repack_archive(members, anon_dir, output_tgz)
            mapping_path = mapping_sidecar_path(output_tgz)
            mapping_path.write_text(
                json.dumps(anon.get_mapping(), indent=2, ensure_ascii=False), encoding="utf-8"
            )
            progress("repack", 1, 1, "")

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
