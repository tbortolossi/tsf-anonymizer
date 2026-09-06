"""Compare mode — prove the anonymization lost nothing it should not have.

This module deliberately does **not** call the anonymizer. It reads two
trees (original and anonymized) plus the mapping sidecar and asks four
independent questions per file:

1. **Is every difference explained by the mapping?** Files are compared line
   by line (an anonymization never adds or removes lines — a line-count
   mismatch is an error). For a changed line, the original is rewritten with
   a plain token → replacement lookup built *only* from the mapping; if the
   result is the anonymized line, the change is explained. Otherwise the
   changed spans are inspected individually, and what remains is reported as
   *unexplained* for a human to look at.
2. **Did anything identifying survive?** Every mapping key is searched in the
   anonymized text (token-level, same boundaries the anonymizer uses). Binary
   files are scanned too — they are copied through untouched, so a rule name
   inside ``rule-hit-count.bin`` is a leak the anonymizer cannot fix, and the
   operator must know about it.
3. **Is the structure intact?** Timestamps and short numeric tokens (counters,
   PIDs, sizes) are counted on both sides and must agree; XML documents must
   parse to the same tag sequence.
4. **Are the untouched files byte-identical?** Binary payloads are hashed.

Archive-level: member list, order, type and metadata (mode, uid/gid, mtime)
must be identical between the two archives.
"""

from __future__ import annotations

import difflib
import gzip
import ipaddress
import multiprocessing
import re
import tarfile
import tempfile
import xml.etree.ElementTree as ET
from collections.abc import Callable
from concurrent.futures import ProcessPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .core import (
    BINARY_EXTENSIONS,
    MAPPING_CATEGORIES,
    REDACTED_PAYLOAD,
    _sub_lowered,
    extract_archive,
    is_binary_bytes,
    lowered_for_ci_scan,
    mapped_member_name,
    trie_regex,
)

ProgressFn = Callable[[str, int, int, str], None]


def _noop(phase: str, done: int, total: int, message: str) -> None:
    pass


_TOKEN_RE = re.compile(r"[\w][\w.\-@]*")
_TIMESTAMP_RE = re.compile(
    r"\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}"
    r"|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d{1,2} \d{2}:\d{2}:\d{2}\b"
)
# "-" is excluded on both sides so a pseudonym like ZONE-0001 does not count as
# a numeric token on one side only. Symmetric: GW-Site-12 is excluded too.
_NUMERIC_TOKEN_RE = re.compile(r"(?<![\w.\-])\d{1,11}(?![\w.\-])")
_MAX_LINE_CHARS = 4000


# ---------------------------------------------------------------------------
# Mapping lookup
# ---------------------------------------------------------------------------

class MappingIndex:
    """Token-level view of the mapping sidecar.

    Two compiled trie regexes do the heavy lifting in C: one case-sensitive
    over every key, one case-insensitive over the FQDN/e-mail keys. A real
    TSF maps ~100 000 identifiers over ~1 GB of text; anything that runs a
    Python callback per *token* (rather than per *hit*) takes tens of minutes.
    """

    # Same boundary conventions as the anonymizer (this is tokenisation, not
    # a decision — every decision still comes from the sidecar): a key is a
    # whole token; never right after "<" / "</" (an XML tag), never before "="
    # (an attribute) or "://" (a URL scheme). "@" and "/" before are fine —
    # "@Mail.Ru", "https://vpn.acme.fr/".
    # "vsys<n>_" is the one underscore that separates (vsys1_<EDL>.ebl).
    _BEFORE = r"(?:(?<![\w.\-<])|(?<=vsys\d_))(?<!<\/)(?<!\/\/)"
    _AFTER = r"(?:(?![\w\-=])|(?=(?:19|20)\d\d-\d\d-\d\d))(?!:\/\/)"

    def __init__(self, mapping: dict) -> None:
        self.mapping = mapping
        self.forward: dict[str, str] = {}    # exact key → fake
        self.forward_ci: dict[str, str] = {}  # lowercased key → fake (fqdns, emails)
        self.category_of: dict[str, str] = {}
        for cat in MAPPING_CATEGORIES:
            for orig, fake in (mapping.get(cat) or {}).items():
                if not orig or orig == fake:
                    continue
                self.forward[orig] = fake
                self.category_of[orig] = cat
                if cat in ("fqdns", "emails"):
                    self.forward_ci[orig.lower()] = fake
        # Distinct originals sharing one pseudonym is a defect of the mapping
        # itself (a generator bug once merged tens of thousands of distinct
        # public sources on a real TSF): the copies cannot be told apart, so
        # correlation on the anonymized tree is silently wrong. Reported in
        # the summary; the anonymizer guarantees injectivity on its side.
        counts: dict[str, int] = {}
        for v in self.forward.values():
            counts[v] = counts.get(v, 0) + 1
        self.duplicate_pseudonyms = sorted(v for v, c in counts.items() if c > 1)
        # A key that is also a fake value somewhere in the mapping (the customer
        # used 100.64.0.3, which is also what we hand out) cannot be told apart
        # from that fake in the output: it is a collision, not a leak, and is
        # reported as such rather than scanned for.
        values = set(self.forward.values())
        self.collisions = sorted(k for k in self.forward if k in values)
        # They stay in `forward`: the anonymizer did rewrite them in the
        # original, so `apply` must too — dropping them once left every
        # occurrence of such a key "unexplained". Only the leak scan skips
        # them: in the *output* the same string is somebody's pseudonym.
        self._collision_keys = set(self.collisions) | {k.lower() for k in self.collisions}
        # IPs and serials sit inside hyphenated/underscored tokens all the time
        # (lr-203.0.113.184-2, PA_001901000456_dt): digit boundaries, not
        # token boundaries, or 100 000 real-TSF lines read as unexplained.
        num_keys = [k for k in self.forward if self.category_of[k] in ("ip_addresses", "serial_numbers")]
        cs_keys = [k for k in self.forward
                   if k.lower() not in self.forward_ci and self.category_of[k]
                   not in ("ip_addresses", "serial_numbers")]
        self._num_re = (re.compile(r"(?<![.\d])" + trie_regex(num_keys) + r"(?!\d)(?!\.\d)")
                        if num_keys else None)
        self._cs_re = (re.compile(self._BEFORE + trie_regex(cs_keys) + self._AFTER)
                       if cs_keys else None)
        # FQDN keys may follow a dot (*.apex, sub.apex), and "_" is a
        # separator for them (a hostname cannot contain one; PAN-OS glues the
        # device name with underscores in techsupport_<name>_<date>.txt) —
        # mirrors the core's boundaries exactly.
        # Compiled twice from one pattern: without IGNORECASE for the scan of
        # a lowered copy of the text (the fast path — the flag costs 2.3x on a
        # trie this size, and this is the most expensive of the three passes,
        # run once by `apply` and once by `find_leaks`), with it for the text
        # that scan cannot serve. `forward_ci` is keyed lowercase already.
        ci_pattern = (r"(?<![A-Za-z0-9<])(?<!<\/)" + trie_regex(self.forward_ci)
                      + r"(?:(?![A-Za-z0-9=])|(?=(?:19|20)\d\d-\d\d-\d\d))(?!:\/\/)"
                      ) if self.forward_ci else ""
        self._ci_re = re.compile(ci_pattern, re.IGNORECASE) if ci_pattern else None
        self._ci_low_re = re.compile(ci_pattern) if ci_pattern else None
        # Minimum key length that the leak scan will bother with. Below 3 the
        # false-positive rate makes the report useless.
        self.min_leak_len = 3

    def lookup(self, token: str) -> str | None:
        fake = self.forward.get(token)
        if fake is not None:
            return fake
        fake = self.forward_ci.get(token.lower())
        if fake is not None:
            return fake
        stripped = token.rstrip(".")
        if stripped != token:
            return self.lookup(stripped) if stripped else None
        return None

    def apply(self, text: str) -> str:
        """Rewrite `text` with mapping keys → fakes. Callbacks run per hit only.

        Pass order mirrors the anonymizer's (fqdns/emails, then objects/users,
        then IPs/serials) — not because this asks the anonymizer anything, but
        because a key can contain another category's key: an address object
        named `FW-Outside-10.30.135.97` is one FQDN-mapped identity, and
        applying the IP first would destroy that key and leave 11 000 real
        lines "unexplained"."""
        if self._ci_re is not None:
            src = text

            def keep(start: int, end: int) -> bool:
                # mirrors the core: `-key>` is an XML tag name, not a hostname
                return not (start and src[start - 1] == "-" and src[end:end + 1] == ">")

            low = lowered_for_ci_scan(text)
            if low is None:   # rare: see lowered_for_ci_scan
                def ci(m: re.Match) -> str:
                    if not keep(m.start(), m.end()):
                        return m.group(0)
                    return self.forward_ci.get(m.group(0).lower(), m.group(0))
                text = self._ci_re.sub(ci, text)
            else:
                text = _sub_lowered(
                    self._ci_low_re, low, text,
                    # `low` is lowercase, so the key needs no folding here.
                    lambda m, s, e: self.forward_ci.get(m.group(0)) if keep(s, e) else None)[0]
        if self._cs_re is not None:
            text = self._cs_re.sub(lambda m: self.forward.get(m.group(0), m.group(0)), text)
        if self._num_re is not None:
            text = self._num_re.sub(lambda m: self.forward.get(m.group(0), m.group(0)), text)
        return text

    def find_leaks(self, text: str) -> dict[str, int]:
        """Mapping keys still present in `text` → occurrence count."""
        hits: dict[str, int] = {}
        for rx in (self._num_re, self._cs_re):
            if rx is None:
                continue
            for m in rx.finditer(text):
                k = m.group(0)
                if len(k) >= self.min_leak_len and k not in self._collision_keys:
                    hits[k] = hits.get(k, 0) + 1
        if self._ci_re is not None:
            low = lowered_for_ci_scan(text)
            # The keys are lowercase, so a hit found in the lowered copy needs
            # no folding; the IGNORECASE fallback still does.
            for m in (self._ci_low_re.finditer(low) if low is not None
                      else self._ci_re.finditer(text)):
                k = m.group(0) if low is not None else m.group(0).lower()
                if len(k) >= self.min_leak_len and k not in self._collision_keys:
                    hits[k] = hits.get(k, 0) + 1
        return hits


# ---------------------------------------------------------------------------
# Per-file analysis
# ---------------------------------------------------------------------------

@dataclass
class FileReport:
    path: str
    kind: str          # text | gz_text | binary | gz_binary | missing | extra | dir
    status: str        # identical | anonymized | warning | error
    orig_size: int = 0
    anon_size: int = 0
    lines_orig: int = 0
    lines_anon: int = 0
    changed_lines: int = 0
    explained_lines: int = 0
    unexplained_lines: int = 0
    unexplained_sample: list[int] = field(default_factory=list)  # 1-based line numbers
    leaks: dict[str, int] = field(default_factory=dict)
    leak_count: int = 0
    timestamps_orig: int = 0
    timestamps_anon: int = 0
    numeric_orig: int = 0
    numeric_anon: int = 0
    xml_structure: str | None = None  # preserved | changed | unparseable
    binary_identical: bool | None = None
    redacted: bool = False
    notes: list[str] = field(default_factory=list)


def _read_payload(path: Path) -> tuple[bytes, str]:
    """Returns (payload, kind) where gz payloads are decompressed."""
    if path.suffix == ".gz":
        try:
            with gzip.open(path, "rb") as f:
                raw = f.read()
        except Exception:
            return path.read_bytes(), "binary"
        return raw, ("gz_binary" if is_binary_bytes(raw[:4096]) else "gz_text")
    raw = path.read_bytes()
    if path.suffix.lower() in BINARY_EXTENSIONS or is_binary_bytes(raw[:4096]):
        return raw, "binary"
    return raw, "text"


def _decode(raw: bytes) -> str:
    return raw.decode("utf-8", errors="surrogateescape")


def _split_lines(text: str) -> list[str]:
    return text.split("\n")


_LONG_LINE = 2000
_MAX_TOKENS = 4000


def _changed_spans(a: str, b: str) -> list[tuple[int, int, int, int]]:
    """Character-level for normal lines. difflib is quadratic, and a real TSF
    has 24 000-character XML lines: those are diffed token by token, and past
    _MAX_TOKENS the whole line is one span (it is then simply unexplained)."""
    if len(a) + len(b) <= _LONG_LINE:
        sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
        return [(i1, i2, j1, j2) for tag, i1, i2, j1, j2 in sm.get_opcodes() if tag != "equal"]
    ta = [(m.start(), m.end()) for m in re.finditer(r"\S+", a)]
    tb = [(m.start(), m.end()) for m in re.finditer(r"\S+", b)]
    if len(ta) > _MAX_TOKENS or len(tb) > _MAX_TOKENS or not ta or not tb:
        return [(0, len(a), 0, len(b))]
    sm = difflib.SequenceMatcher(None, [a[s:e] for s, e in ta], [b[s:e] for s, e in tb])
    out = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            continue
        oa = (ta[i1][0], ta[i2 - 1][1]) if i2 > i1 else (ta[i1][0] if i1 < len(ta) else len(a),) * 2
        ob = (tb[j1][0], tb[j2 - 1][1]) if j2 > j1 else (tb[j1][0] if j1 < len(tb) else len(b),) * 2
        out.append((oa[0], oa[1], ob[0], ob[1]))
    return out


def _expand_to_token(s: str, start: int, end: int) -> tuple[int, int]:
    while start > 0 and (s[start - 1].isalnum() or s[start - 1] in "._-@"):
        start -= 1
    while end < len(s) and (s[end].isalnum() or s[end] in "._-@"):
        end += 1
    return start, end


def explain_line(orig: str, anon: str, index: MappingIndex) -> bool:
    """True when the whole difference between the two lines is mapping-driven."""
    if index.apply(orig) == anon:
        return True
    for i1, i2, j1, j2 in _changed_spans(orig, anon):
        oi1, oi2 = _expand_to_token(orig, i1, i2)
        aj1, aj2 = _expand_to_token(anon, j1, j2)
        o_span, a_span = orig[oi1:oi2], anon[aj1:aj2]
        if index.apply(o_span) == a_span:
            continue
        fake = index.lookup(o_span)
        if fake is not None and fake == a_span:
            continue
        return False
    return True


def analyze_text_pair(rel: str, orig_raw: bytes, anon_raw: bytes, kind: str,
                      index: MappingIndex, xml: bool) -> FileReport:
    rep = FileReport(path=rel, kind=kind, status="identical",
                     orig_size=len(orig_raw), anon_size=len(anon_raw))
    o_text, a_text = _decode(orig_raw), _decode(anon_raw)
    o_lines, a_lines = _split_lines(o_text), _split_lines(a_text)
    rep.lines_orig, rep.lines_anon = len(o_lines), len(a_lines)

    leaks = index.find_leaks(a_text)
    rep.leaks = dict(sorted(leaks.items(), key=lambda kv: -kv[1])[:50])
    rep.leak_count = sum(leaks.values())

    if rep.lines_orig != rep.lines_anon:
        rep.status = "error"
        rep.notes.append(f"line count changed: {rep.lines_orig} → {rep.lines_anon}")
        rep.changed_lines = sum(1 for o, a in zip(o_lines, a_lines, strict=False) if o != a)
        return rep

    if o_text != a_text:
        # One C-level rewrite of the whole file; a line the mapping explains is
        # then byte-equal and costs no Python at all. Only the residue goes
        # through the per-line span analysis.
        e_lines = _split_lines(index.apply(o_text))
        unexplained_pairs: list[tuple[int, str, str]] = []
        for n, (o, a, e) in enumerate(zip(o_lines, a_lines, e_lines, strict=False), 1):
            if o == a:
                continue
            rep.changed_lines += 1
            if e == a or explain_line(o, a, index):
                rep.explained_lines += 1
            else:
                rep.unexplained_lines += 1
                if len(rep.unexplained_sample) < 20:
                    rep.unexplained_sample.append(n)
                if len(unexplained_pairs) < 10_000:
                    unexplained_pairs.append((n, o, a))
        # Timestamps and short numeric tokens can only have moved on lines
        # the mapping does not explain (a mapping key is never a timestamp or
        # a short number), so the counts are taken there — over a whole TSF
        # the full-corpus count was minutes of work to report the same thing.
        o_res = "\n".join(o for _, o, _ in unexplained_pairs)
        a_res = "\n".join(a for _, _, a in unexplained_pairs)
        rep.timestamps_orig = len(_TIMESTAMP_RE.findall(o_res))
        rep.timestamps_anon = len(_TIMESTAMP_RE.findall(a_res))
        rep.numeric_orig = len(_NUMERIC_TOKEN_RE.findall(o_res))
        rep.numeric_anon = len(_NUMERIC_TOKEN_RE.findall(a_res))

    if xml and o_text != a_text:
        rep.xml_structure = _xml_structure(o_text, a_text)
        if rep.xml_structure == "changed":
            rep.notes.append("XML tag sequence differs")

    if rep.changed_lines:
        rep.status = "anonymized"
    if rep.timestamps_orig != rep.timestamps_anon:
        rep.notes.append(f"timestamp count changed: {rep.timestamps_orig} → {rep.timestamps_anon}")
    if rep.numeric_orig != rep.numeric_anon:
        rep.notes.append(f"numeric token count changed: {rep.numeric_orig} → {rep.numeric_anon}")
    if rep.unexplained_lines:
        rep.notes.append(f"{rep.unexplained_lines} line(s) changed beyond the mapping")
    if rep.leak_count:
        rep.notes.append(f"{rep.leak_count} occurrence(s) of mapped identifiers survive")
    if rep.notes or rep.xml_structure == "changed":
        rep.status = "warning"
    if rep.xml_structure == "changed" or rep.leak_count:
        rep.status = "error"
    return rep


def _xml_structure(o_text: str, a_text: str) -> str:
    try:
        o_root = ET.fromstring(o_text)
        a_root = ET.fromstring(a_text)
    except ET.ParseError:
        return "unparseable"
    o_tags = [e.tag for e in o_root.iter()]
    a_tags = [e.tag for e in a_root.iter()]
    return "preserved" if o_tags == a_tags else "changed"


def analyze_binary_pair(rel: str, orig_raw: bytes, anon_raw: bytes, kind: str,
                        index: MappingIndex) -> FileReport:
    rep = FileReport(path=rel, kind=kind, status="identical",
                     orig_size=len(orig_raw), anon_size=len(anon_raw))
    # Both payloads are already in memory: a plain compare beats hashing them.
    rep.binary_identical = orig_raw == anon_raw
    if not rep.binary_identical:
        rep.status = "error"
        rep.notes.append("binary payload changed")
        return rep
    # Latin-1 never fails, so identifiers embedded in a binary are findable.
    leaks = index.find_leaks(anon_raw.decode("latin-1"))
    if leaks:
        rep.leaks = dict(sorted(leaks.items(), key=lambda kv: -kv[1])[:50])
        rep.leak_count = sum(leaks.values())
        rep.status = "warning"
        rep.notes.append(
            f"{rep.leak_count} mapped identifier(s) present in an untouched binary file"
        )
    return rep


# ---------------------------------------------------------------------------
# Tree / archive comparison
# ---------------------------------------------------------------------------

@dataclass
class CompareReport:
    summary: dict = field(default_factory=dict)
    archive: dict = field(default_factory=dict)
    files: list[FileReport] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {"summary": self.summary, "archive": self.archive,
                "files": [asdict(f) for f in self.files]}

    @property
    def ok(self) -> bool:
        return self.summary.get("errors", 0) == 0 and not self.archive.get("mismatches")


def _walk(tree: Path) -> dict[str, Path]:
    return {str(p.relative_to(tree)): p for p in sorted(tree.rglob("*")) if p.is_file()}


def compare_one(rel: str, o_path: Path, a_path: Path, index: MappingIndex) -> FileReport:
    """Analyse one pair. Pure: a mapping in, a report out — nothing shared,
    which is what makes the pass safe to spread over processes."""
    try:
        o_raw, o_kind = _read_payload(o_path)
        a_raw, a_kind = _read_payload(a_path)
    except Exception as e:
        return FileReport(rel, "text", "error", notes=[f"unreadable: {e}"])
    if a_raw == REDACTED_PAYLOAD and o_kind in ("binary", "gz_binary"):
        # A declared redaction. Verified, not trusted: the original must
        # actually embed mapped identifiers, or the data loss was gratuitous.
        rep = FileReport(rel, o_kind, "anonymized", orig_size=len(o_raw),
                         anon_size=len(a_raw), redacted=True)
        occurrences = sum(index.find_leaks(o_raw.decode("latin-1")).values())
        if occurrences:
            rep.notes.append(f"binary payload redacted "
                             f"({occurrences} embedded identifier occurrence(s) in the original)")
        else:
            rep.status = "warning"
            rep.notes.append("binary payload redacted, but no mapped identifier "
                             "was found in the original")
        return rep
    if o_kind in ("binary", "gz_binary"):
        return analyze_binary_pair(rel, o_raw, a_raw, o_kind, index)
    if a_kind in ("binary", "gz_binary"):
        return FileReport(rel, o_kind, "error", orig_size=len(o_raw), anon_size=len(a_raw),
                          notes=["text file became binary"])
    return analyze_text_pair(rel, o_raw, a_raw, o_kind, index,
                             xml=rel.lower().endswith(".xml"))


# One MappingIndex per worker process, built once by the initializer: compiling
# the trie over ~100 000 identifiers is the expensive part, and it must not be
# paid per file.
_WORKER: tuple[MappingIndex, Path, Path] | None = None


def _init_worker(mapping: dict, orig_dir: str, anon_dir: str) -> None:
    global _WORKER
    _WORKER = (MappingIndex(mapping), Path(orig_dir), Path(anon_dir))


def _analyze_in_worker(pair: tuple[str, str]) -> FileReport:
    rel, a_rel = pair
    index, orig_dir, anon_dir = _WORKER
    try:
        return compare_one(rel, orig_dir / rel, anon_dir / a_rel, index)
    except Exception as e:  # a worker crash must cost one file, not the report
        return FileReport(rel, "text", "error", notes=[f"comparison failed: {e}"])


_RIB_ROW_RE = re.compile(
    r"^\s*(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\s+(?:\S+\s+)?(\d{1,3}(?:\.\d{1,3}){3})?")


_PRESERVED_SPACES = tuple(ipaddress.ip_network(c) for c in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"))


def _in_preserved(net) -> bool:
    """Prefix preservation is guaranteed for RFC 1918/CGNAT only; public
    space keeps /24 grouping but not aggregation (documented). A relation is
    load-bearing for the check iff every network involved is private."""
    return net.version == 4 and any(net.subnet_of(p) for p in _PRESERVED_SPACES)


def _routing_view(tree: Path) -> dict | None:
    """One side's routing topology, re-derived from that tree alone: the
    connected networks (config layer3 IPs + the RIB's connected rows), and
    the routes of the config's static-route entries plus the RIB rows of
    both `show routing route` formats (classic and advanced-routing). The
    same code runs on the original and on the anonymized tree — no mapping,
    no anonymizer. A `.merged-running-config.xml` wins over
    `running-config.xml`: on a Panorama-managed device the latter ships an
    empty <interface> section (real box, 0 connected networks found)."""
    cfgs = (sorted(tree.rglob(".merged-running-config.xml"))
            or sorted(tree.rglob("running-config.xml")))
    if not cfgs:
        return None
    try:
        root = ET.parse(cfgs[0]).getroot()
    except ET.ParseError:
        return None
    connected: list = []
    for lay in root.iter("layer3"):
        for ip_el in lay.iter("ip"):
            for e in ip_el.findall("entry"):
                name = e.get("name") or ""
                if "/" in name:
                    try:
                        connected.append(ipaddress.ip_network(name, strict=False))
                    except ValueError:
                        pass
    routes: list = []  # (network, nexthop | None)
    for sr in root.iter("static-route"):
        for e in sr.findall(".//entry"):
            dest = e.findtext("destination")
            if not dest:
                continue
            nh = e.findtext("nexthop/ip-address")
            try:
                routes.append((ipaddress.ip_network(dest, strict=False),
                               ipaddress.ip_address(nh) if nh else None, dest))
            except ValueError:
                continue
    for ts in sorted((tree / "tmp" / "cli").glob("techsupport_*.txt")):
        try:
            text = ts.read_bytes().decode("utf-8", "surrogateescape")
        except OSError:
            continue
        for m in re.finditer(r"^> show (?:advanced-)?routing route.*?(?=^> |\Z)",
                             text, re.S | re.M):
            for line in m.group(0).splitlines()[1:]:
                rm = _RIB_ROW_RE.match(line)
                if not rm:
                    continue
                try:
                    dest_net = ipaddress.ip_network(rm.group(1), strict=False)
                    nh_addr = ipaddress.ip_address(rm.group(2)) if rm.group(2) else None
                except ValueError:
                    continue
                routes.append((dest_net, nh_addr, rm.group(1)))
                # a "C"-flagged / connected row is a connected network too —
                # the only source of them on a Panorama-managed box whose
                # shipped configs carry no <interface> addresses at all
                if nh_addr is None and re.search(r"\bA?\s*C\b|\bconnected\b", line):
                    connected.append(dest_net)
    # Containment over unique networks via ancestor sets (a real RIB has
    # 6 903 rows: 24 M O(n^2) pairs took minutes; ancestors are n x #plens).
    uniq: list = []
    index: dict = {}
    for d, _, raw in routes:
        if raw not in index:
            index[raw] = len(uniq)
            uniq.append(d)
    by_plen: dict[int, dict[int, int]] = {}
    for i, d in enumerate(uniq):
        by_plen.setdefault(d.prefixlen, {})[int(d.network_address)] = i
    def ancestors(net) -> list[int]:
        a = int(net.network_address)
        out = []
        for plen, table in by_plen.items():
            if plen > net.prefixlen:
                continue
            j = table.get(a >> (32 - plen) << (32 - plen) if plen else 0)
            if j is not None and uniq[j].prefixlen == plen:
                out.append(j)
        return sorted(out)
    return {
        "routes": len(routes),
        "connected": len(connected),
        "prefixlens": [d.prefixlen for d, _, _ in routes] + [c.prefixlen for c in connected],
        "preserved": ([_in_preserved(d) for d, _, _ in routes]
                      + [_in_preserved(c) for c in connected]),
        "nexthop_in_connected": [nh is not None and any(nh in c for c in connected)
                                 for _, nh, _ in routes],
        "route_of": [index[raw] for _, _, raw in routes],
        "containment": [ancestors(d) for d in uniq],
        "uniq_preserved": [_in_preserved(d) for d in uniq],
        "connected_in_route": [c.subnet_of(d) for c in connected for d in uniq],
    }


def check_routing_coherence(orig_dir: Path, anon_dir: Path) -> dict:
    """Every structural relation must hold on the anonymized tree iff it
    holds on the original. Any injective mapping explains every *line*; only
    a prefix-preserving one keeps these *relations* — this is the check that
    fails if prefix preservation ever regresses."""
    o, a = _routing_view(orig_dir), _routing_view(anon_dir)
    out: dict = {"checked": False}
    if o is None or a is None:
        return out
    out.update(checked=True, routes=o["routes"], connected=o["connected"])
    mismatches: list[str] = []
    public = 0
    if (o["routes"] != a["routes"] or o["connected"] != a["connected"]
            or o["route_of"] != a["route_of"]):
        mismatches.append(
            f"structure differs: {o['routes']} routes / {o['connected']} connected"
            f" vs {a['routes']} / {a['connected']}")
    else:
        for key, label, keep in (
                ("prefixlens", "prefix length", o["preserved"]),
                ("nexthop_in_connected", "nexthop-in-connected-subnet",
                 o["preserved"][:o["routes"]]),
                ("containment", "route-containment", o["uniq_preserved"]),
                ("connected_in_route", "connected-network-in-route", None)):
            if keep is None:  # connected x uniq grid: private iff both are
                keep = [cp and up for cp in o["preserved"][o["routes"]:]
                        for up in o["uniq_preserved"]]
            bad = pub = 0
            for x, y, p in zip(o[key], a[key], keep, strict=True):
                if x != y:
                    if p:
                        bad += 1
                    else:
                        pub += 1
            public += pub
            if bad:
                mismatches.append(f"{bad} {label} relation(s) hold on one side only")
    out["mismatches"] = mismatches
    # Public aggregation (anything beyond the per-/24 grouping) is the
    # documented trade of mapping public space into 240/4: counted, shown,
    # but not an error — private structure is the guarantee.
    out["public_divergences"] = public
    out["ok"] = not mismatches
    return out


def compare_trees(orig_dir: Path, anon_dir: Path, mapping: dict,
                  progress: ProgressFn = _noop, workers: int = 1) -> CompareReport:
    """Compare two extracted trees.

    `workers` > 1 spreads the per-file analysis over processes. The pass is a
    pure function of the sidecar, so this changes nothing but the wall clock:
    the reports are collected back in path order, and a worker that dies on one
    file costs that file, not the run.
    """
    index = MappingIndex(mapping)
    report = CompareReport()
    o_files, a_files = _walk(orig_dir), _walk(anon_dir)
    # Member names carry identifiers too (techsupport_<devicename>_<date>.txt),
    # so the anonymized side is looked up under the *mapped* name first — the
    # same mapping, applied to the path — and under the original name second
    # (an anonymize job's working trees keep the original names on disk).
    a_rel_of: dict[str, str | None] = {}
    for rel in o_files:
        mapped = mapped_member_name(index.apply, rel)
        a_rel_of[rel] = mapped if mapped in a_files else (rel if rel in a_files else None)
    matched = {v for v in a_rel_of.values() if v}
    renamed = sum(1 for rel, a_rel in a_rel_of.items() if a_rel and a_rel != rel)
    all_paths = sorted(set(o_files) | {a for a in a_files if a not in matched})
    total = len(all_paths)

    done: dict[str, FileReport] = {}
    pairs: list[tuple[str, str]] = []
    for rel in all_paths:
        if rel in o_files and a_rel_of[rel] is None:
            done[rel] = FileReport(rel, "missing", "error",
                                   orig_size=o_files[rel].stat().st_size,
                                   notes=["missing from anonymized archive"])
        elif rel not in o_files:
            done[rel] = FileReport(rel, "extra", "error",
                                   anon_size=a_files[rel].stat().st_size,
                                   notes=["not present in the original archive"])
        else:
            pairs.append((rel, a_rel_of[rel]))

    if workers > 1 and len(pairs) > 1:
        # forkserver, not fork: this runs on a worker thread of a live server,
        # and forking a threaded process inherits locks held by other threads.
        ctx = multiprocessing.get_context("forkserver")
        with ProcessPoolExecutor(max_workers=workers, mp_context=ctx,
                                 initializer=_init_worker,
                                 initargs=(mapping, str(orig_dir), str(anon_dir))) as pool:
            for i, ((rel, _), rep) in enumerate(
                    zip(pairs, pool.map(_analyze_in_worker, pairs, chunksize=4), strict=True), 1):
                done[rel] = rep
                if i % 25 == 0 or i == len(pairs):
                    progress("compare", i, total, rel)
    else:
        for i, (rel, a_rel) in enumerate(pairs, 1):
            done[rel] = compare_one(rel, o_files[rel], a_files[a_rel], index)
            if i % 25 == 0 or i == len(pairs):
                progress("compare", i, total, rel)

    report.files = [done[rel] for rel in all_paths]
    report.summary = summarize(report.files)
    report.summary["members_renamed"] = renamed
    report.summary["mapping_collisions"] = len(index.collisions)
    report.summary["mapping_collision_sample"] = index.collisions[:20]
    report.summary["mapping_duplicate_pseudonyms"] = len(index.duplicate_pseudonyms)
    report.summary["mapping_duplicate_sample"] = index.duplicate_pseudonyms[:20]
    report.summary["routing"] = check_routing_coherence(orig_dir, anon_dir)
    return report


def summarize(files: list[FileReport]) -> dict:
    s = {
        "files_total": len(files),
        "identical": 0, "anonymized": 0, "warnings": 0, "errors": 0,
        "text_files": 0, "binary_files": 0, "binary_identical": 0,
        "changed_lines": 0, "explained_lines": 0, "unexplained_lines": 0,
        "line_count_mismatches": 0,
        "leaks_total": 0, "files_with_leaks": 0, "binary_files_with_identifiers": 0,
        "binary_redacted": 0,
        "timestamp_mismatches": 0, "numeric_mismatches": 0,
        "xml_checked": 0, "xml_structure_changed": 0,
    }
    for f in files:
        s[{"identical": "identical", "anonymized": "anonymized",
           "warning": "warnings", "error": "errors"}[f.status]] += 1
        if f.kind in ("text", "gz_text"):
            s["text_files"] += 1
        if f.kind in ("binary", "gz_binary"):
            s["binary_files"] += 1
            if f.binary_identical:
                s["binary_identical"] += 1
            if f.leak_count:
                s["binary_files_with_identifiers"] += 1
            if f.redacted:
                s["binary_redacted"] += 1
        s["changed_lines"] += f.changed_lines
        s["explained_lines"] += f.explained_lines
        s["unexplained_lines"] += f.unexplained_lines
        if f.kind in ("text", "gz_text") and f.lines_orig != f.lines_anon:
            s["line_count_mismatches"] += 1
        if f.kind in ("text", "gz_text") and f.leak_count:
            s["leaks_total"] += f.leak_count
            s["files_with_leaks"] += 1
        if f.timestamps_orig != f.timestamps_anon:
            s["timestamp_mismatches"] += 1
        if f.numeric_orig != f.numeric_anon:
            s["numeric_mismatches"] += 1
        if f.xml_structure in ("preserved", "changed"):
            s["xml_checked"] += 1
            if f.xml_structure == "changed":
                s["xml_structure_changed"] += 1
    s["ok"] = s["errors"] == 0
    return s


def compare_members(orig_tgz: Path, anon_tgz: Path,
                    progress: ProgressFn = _noop, mapping: dict | None = None) -> dict:
    """Archive-level check: same members, same order, same metadata.

    Member names are compared through the mapping: a name that carries an
    identifier (techsupport_<devicename>_<date>.txt) is expected to come out
    renamed, exactly as the text would.

    Reading a member list decompresses the whole archive; on a real TSF that
    is minutes *per side*, so each side reports — a 0/1 bar sat quiet for
    14 minutes on a real run and could not be told from a hang.
    """
    def load(p: Path) -> list[tarfile.TarInfo]:
        with tarfile.open(p, "r:*") as tar:
            return [m for m in tar.getmembers() if m.name.lstrip("/") not in ("", ".")]
    progress("verify", 0, 2, f"Reading members of {orig_tgz.name}")
    o = load(orig_tgz)
    progress("verify", 1, 2, f"Reading members of {anon_tgz.name}")
    a = load(anon_tgz)
    progress("verify", 2, 2, "")
    index = MappingIndex(mapping or {})
    mismatches: list[str] = []
    o_names = [mapped_member_name(index.apply, m.name.lstrip("/")) for m in o]
    a_names = [m.name.lstrip("/") for m in a]
    if o_names != a_names:
        missing = sorted(set(o_names) - set(a_names))
        extra = sorted(set(a_names) - set(o_names))
        if missing:
            mismatches.append(f"{len(missing)} member(s) missing: {missing[:5]}")
        if extra:
            mismatches.append(f"{len(extra)} extra member(s): {extra[:5]}")
        if not missing and not extra:
            mismatches.append("member order differs")
    a_by = {m.name.lstrip("/"): m for m in a}
    meta_diff = 0
    for m, expected in zip(o, o_names, strict=True):
        n = a_by.get(expected)
        if n is None:
            continue
        if (m.type, m.mode, m.uid, m.gid, m.mtime) != (n.type, n.mode, n.uid, n.gid, n.mtime):
            meta_diff += 1
    if meta_diff:
        mismatches.append(f"{meta_diff} member(s) with different metadata (mode/uid/gid/mtime)")
    return {
        "members_orig": len(o), "members_anon": len(a),
        "members_renamed": sum(1 for m, e in zip(o, o_names, strict=True) if m.name.lstrip("/") != e),
        "order_preserved": o_names == a_names,
        "metadata_differences": meta_diff,
        "mismatches": mismatches,
    }


def compare_archives(orig_tgz: Path, anon_tgz: Path, mapping: dict,
                     work_root: Path | None = None, keep_trees: bool = False,
                     progress: ProgressFn = _noop, workers: int = 1) -> CompareReport:
    import shutil

    tmp_ctx = tempfile.TemporaryDirectory(prefix="tsf_cmp_") if work_root is None else None
    root = Path(tmp_ctx.name) if tmp_ctx else work_root
    root.mkdir(parents=True, exist_ok=True)
    try:
        # Each extraction counts its own members; the archive name in the
        # message is what says which of the two is being read.
        extract_archive(orig_tgz, root / "orig", progress=progress)
        extract_archive(anon_tgz, root / "anon", progress=progress)
        report = compare_trees(root / "orig", root / "anon", mapping, progress, workers=workers)
        report.archive = compare_members(orig_tgz, anon_tgz, progress, mapping)
        if not keep_trees and work_root is not None:
            shutil.rmtree(root / "orig", ignore_errors=True)
            shutil.rmtree(root / "anon", ignore_errors=True)
    finally:
        if tmp_ctx:
            tmp_ctx.cleanup()
    return report


# ---------------------------------------------------------------------------
# Diff view for the UI
# ---------------------------------------------------------------------------

def file_diff(orig_dir: Path, anon_dir: Path, rel: str, mapping: dict,
              context: int = 3, max_hunks: int = 200, start_line: int = 1,
              window: int = 0) -> dict:
    """Line-aligned diff hunks with changed-span offsets for highlighting.

    With ``window`` > 0 the raw side-by-side lines from ``start_line`` are
    returned instead of hunks (for a "browse the whole file" view).
    """
    o_path, a_path = orig_dir / rel, anon_dir / rel
    if not a_path.is_file():
        a_path = anon_dir / mapped_member_name(MappingIndex(mapping).apply, rel)  # renamed
    if not o_path.is_file() or not a_path.is_file():
        return {"path": rel, "error": "file missing on one side"}
    o_raw, o_kind = _read_payload(o_path)
    a_raw, a_kind = _read_payload(a_path)
    if o_kind in ("binary", "gz_binary") or a_kind in ("binary", "gz_binary"):
        return {"path": rel, "kind": o_kind, "binary": True,
                "identical": o_raw == a_raw, "orig_size": len(o_raw), "anon_size": len(a_raw)}
    index = MappingIndex(mapping)
    o_lines, a_lines = _split_lines(_decode(o_raw)), _split_lines(_decode(a_raw))
    n = max(len(o_lines), len(a_lines))

    def row(i: int) -> dict:
        o = o_lines[i] if i < len(o_lines) else None
        a = a_lines[i] if i < len(a_lines) else None
        changed = o != a
        r = {"n": i + 1, "orig": _clip(o), "anon": _clip(a), "changed": changed}
        if changed and o is not None and a is not None:
            r["explained"] = explain_line(o, a, index)
            r["spans"] = [list(s) for s in _changed_spans(o[:_MAX_LINE_CHARS], a[:_MAX_LINE_CHARS])]
        return r

    if window > 0:
        s = max(0, start_line - 1)
        rows = [row(i) for i in range(s, min(n, s + window))]
        return {"path": rel, "kind": o_kind, "binary": False, "total_lines": n,
                "start_line": s + 1, "rows": rows}

    changed_idx = [i for i in range(n)
                   if (o_lines[i] if i < len(o_lines) else None)
                   != (a_lines[i] if i < len(a_lines) else None)]
    hunks: list[dict] = []
    i = 0
    truncated = False
    while i < len(changed_idx):
        if len(hunks) >= max_hunks:
            truncated = True
            break
        start = changed_idx[i]
        end = start
        j = i
        while j + 1 < len(changed_idx) and changed_idx[j + 1] - end <= 2 * context + 1:
            j += 1
            end = changed_idx[j]
        lo, hi = max(0, start - context), min(n, end + context + 1)
        hunks.append({"start": lo + 1, "end": hi, "rows": [row(k) for k in range(lo, hi)]})
        i = j + 1
    return {"path": rel, "kind": o_kind, "binary": False, "total_lines": n,
            "changed_lines": len(changed_idx), "hunks": hunks, "truncated": truncated}


def _clip(s: str | None) -> str | None:
    """Display form of a line: clipped, and with the lone surrogates that
    ``surrogateescape`` produces for non-UTF-8 bytes replaced by U+FFFD — JSON
    cannot carry them. Display only; payloads on disk are never touched."""
    if s is None:
        return None
    if len(s) > _MAX_LINE_CHARS:
        s = s[:_MAX_LINE_CHARS] + " …[clipped]"
    return s.encode("utf-8", errors="replace").decode("utf-8")
