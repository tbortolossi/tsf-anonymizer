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
import hashlib
import re
import tarfile
import tempfile
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Optional

from .core import BINARY_EXTENSIONS, MAPPING_CATEGORIES, extract_archive, is_binary_bytes

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
    """Token-level view of the mapping sidecar."""

    def __init__(self, mapping: dict) -> None:
        self.mapping = mapping
        self.forward: dict[str, str] = {}   # exact key → fake
        self.forward_ci: dict[str, str] = {}  # lowercased key → fake (fqdns, emails)
        self.category_of: dict[str, str] = {}
        self.reverse: dict[str, set[str]] = {}
        self.multiword: list[str] = []
        for cat in MAPPING_CATEGORIES:
            for orig, fake in (mapping.get(cat) or {}).items():
                if not orig or orig == fake:
                    continue
                self.forward[orig] = fake
                self.category_of[orig] = cat
                if cat in ("fqdns", "emails"):
                    self.forward_ci[orig.lower()] = fake
                self.reverse.setdefault(fake, set()).add(orig)
                if not _TOKEN_RE.fullmatch(orig):
                    self.multiword.append(orig)
        self.multiword.sort(key=len, reverse=True)
        self._multi_re = (
            re.compile(r"(?<!\w)(" + "|".join(re.escape(k) for k in self.multiword) + r")(?!\w)")
            if self.multiword else None
        )
        # Minimum key length that the leak scan will bother with. Below 3 the
        # false-positive rate makes the report useless.
        self.min_leak_len = 3

    def lookup(self, token: str) -> Optional[str]:
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
        """Rewrite `text` with mapping keys → fakes, token by token."""
        if self._multi_re is not None:
            text = self._multi_re.sub(lambda m: self.forward.get(m.group(1), m.group(1)), text)

        def sub(m: re.Match) -> str:
            tok = m.group(0)
            fake = self.lookup(tok)
            if fake is None:
                return tok
            if tok in self.forward or tok.lower() in self.forward_ci:
                return fake
            # lookup() matched after stripping trailing dots: keep them.
            stripped = tok.rstrip(".")
            return fake + "." * (len(tok) - len(stripped))
        return _TOKEN_RE.sub(sub, text)

    def find_leaks(self, text: str) -> dict[str, int]:
        """Mapping keys still present in `text` → occurrence count."""
        hits: dict[str, int] = {}
        if self._multi_re is not None:
            for m in self._multi_re.finditer(text):
                hits[m.group(1)] = hits.get(m.group(1), 0) + 1
        for m in _TOKEN_RE.finditer(text):
            tok = m.group(0)
            if len(tok) < self.min_leak_len:
                continue
            key = tok if tok in self.forward else None
            if key is None:
                low = tok.lower()
                if low in self.forward_ci:
                    key = low
                else:
                    stripped = tok.rstrip(".")
                    if stripped in self.forward:
                        key = stripped
                    elif stripped.lower() in self.forward_ci:
                        key = stripped.lower()
            if key is not None:
                hits[key] = hits.get(key, 0) + 1
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
    xml_structure: Optional[str] = None  # preserved | changed | unparseable
    binary_identical: Optional[bool] = None
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


def _changed_spans(a: str, b: str) -> list[tuple[int, int, int, int]]:
    sm = difflib.SequenceMatcher(None, a, b, autojunk=False)
    return [(i1, i2, j1, j2) for tag, i1, i2, j1, j2 in sm.get_opcodes() if tag != "equal"]


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

    rep.timestamps_orig = len(_TIMESTAMP_RE.findall(o_text))
    rep.timestamps_anon = len(_TIMESTAMP_RE.findall(a_text))
    rep.numeric_orig = len(_NUMERIC_TOKEN_RE.findall(o_text))
    rep.numeric_anon = len(_NUMERIC_TOKEN_RE.findall(a_text))

    leaks = index.find_leaks(a_text)
    rep.leaks = dict(sorted(leaks.items(), key=lambda kv: -kv[1])[:50])
    rep.leak_count = sum(leaks.values())

    if rep.lines_orig != rep.lines_anon:
        rep.status = "error"
        rep.notes.append(f"line count changed: {rep.lines_orig} → {rep.lines_anon}")
        # Still count changed lines over the common prefix so the UI has something
        for o, a in zip(o_lines, a_lines):
            if o != a:
                rep.changed_lines += 1
        return rep

    for n, (o, a) in enumerate(zip(o_lines, a_lines), 1):
        if o == a:
            continue
        rep.changed_lines += 1
        if explain_line(o, a, index):
            rep.explained_lines += 1
        else:
            rep.unexplained_lines += 1
            if len(rep.unexplained_sample) < 20:
                rep.unexplained_sample.append(n)

    if xml:
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
    rep.binary_identical = hashlib.sha256(orig_raw).digest() == hashlib.sha256(anon_raw).digest()
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


def compare_trees(orig_dir: Path, anon_dir: Path, mapping: dict,
                  progress: ProgressFn = _noop) -> CompareReport:
    index = MappingIndex(mapping)
    report = CompareReport()
    o_files, a_files = _walk(orig_dir), _walk(anon_dir)
    all_paths = sorted(set(o_files) | set(a_files))
    total = len(all_paths)

    for i, rel in enumerate(all_paths, 1):
        if rel not in a_files:
            report.files.append(FileReport(rel, "missing", "error",
                                           orig_size=o_files[rel].stat().st_size,
                                           notes=["missing from anonymized archive"]))
            continue
        if rel not in o_files:
            report.files.append(FileReport(rel, "extra", "error",
                                           anon_size=a_files[rel].stat().st_size,
                                           notes=["not present in the original archive"]))
            continue
        try:
            o_raw, o_kind = _read_payload(o_files[rel])
            a_raw, a_kind = _read_payload(a_files[rel])
        except Exception as e:
            report.files.append(FileReport(rel, "text", "error", notes=[f"unreadable: {e}"]))
            continue
        if o_kind in ("binary", "gz_binary"):
            rep = analyze_binary_pair(rel, o_raw, a_raw, o_kind, index)
        elif a_kind in ("binary", "gz_binary"):
            rep = FileReport(rel, o_kind, "error", orig_size=len(o_raw), anon_size=len(a_raw),
                             notes=["text file became binary"])
        else:
            rep = analyze_text_pair(rel, o_raw, a_raw, o_kind, index,
                                    xml=rel.lower().endswith(".xml"))
        report.files.append(rep)
        if i % 25 == 0 or i == total:
            progress("compare", i, total, rel)

    report.summary = summarize(report.files)
    return report


def summarize(files: list[FileReport]) -> dict:
    s = {
        "files_total": len(files),
        "identical": 0, "anonymized": 0, "warnings": 0, "errors": 0,
        "text_files": 0, "binary_files": 0, "binary_identical": 0,
        "changed_lines": 0, "explained_lines": 0, "unexplained_lines": 0,
        "line_count_mismatches": 0,
        "leaks_total": 0, "files_with_leaks": 0, "binary_files_with_identifiers": 0,
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


def compare_members(orig_tgz: Path, anon_tgz: Path) -> dict:
    """Archive-level check: same members, same order, same metadata."""
    def load(p: Path) -> list[tarfile.TarInfo]:
        with tarfile.open(p, "r:*") as tar:
            return [m for m in tar.getmembers() if m.name.lstrip("/") not in ("", ".")]
    o, a = load(orig_tgz), load(anon_tgz)
    mismatches: list[str] = []
    o_names = [m.name.lstrip("/") for m in o]
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
    for m in o:
        n = a_by.get(m.name.lstrip("/"))
        if n is None:
            continue
        if (m.type, m.mode, m.uid, m.gid, m.mtime) != (n.type, n.mode, n.uid, n.gid, n.mtime):
            meta_diff += 1
    if meta_diff:
        mismatches.append(f"{meta_diff} member(s) with different metadata (mode/uid/gid/mtime)")
    return {
        "members_orig": len(o), "members_anon": len(a),
        "order_preserved": o_names == a_names,
        "metadata_differences": meta_diff,
        "mismatches": mismatches,
    }


def compare_archives(orig_tgz: Path, anon_tgz: Path, mapping: dict,
                     work_root: Optional[Path] = None, keep_trees: bool = False,
                     progress: ProgressFn = _noop) -> CompareReport:
    import shutil

    tmp_ctx = tempfile.TemporaryDirectory(prefix="tsf_cmp_") if work_root is None else None
    root = Path(tmp_ctx.name) if tmp_ctx else work_root
    root.mkdir(parents=True, exist_ok=True)
    try:
        progress("extract", 0, 2, f"Extracting {orig_tgz.name}")
        extract_archive(orig_tgz, root / "orig")
        progress("extract", 1, 2, f"Extracting {anon_tgz.name}")
        extract_archive(anon_tgz, root / "anon")
        progress("extract", 2, 2, "")
        report = compare_trees(root / "orig", root / "anon", mapping, progress)
        report.archive = compare_members(orig_tgz, anon_tgz)
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


def _clip(s: Optional[str]) -> Optional[str]:
    """Display form of a line: clipped, and with the lone surrogates that
    ``surrogateescape`` produces for non-UTF-8 bytes replaced by U+FFFD — JSON
    cannot carry them. Display only; payloads on disk are never touched."""
    if s is None:
        return None
    if len(s) > _MAX_LINE_CHARS:
        s = s[:_MAX_LINE_CHARS] + " …[clipped]"
    return s.encode("utf-8", errors="replace").decode("utf-8")
