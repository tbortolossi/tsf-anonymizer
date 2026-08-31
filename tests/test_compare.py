"""Compare-mode tests: the check must pass on a correct anonymization and fail
on each way an anonymization can go wrong."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from tsf_anonymizer.core import anonymize_tsf
from tsf_anonymizer.compare import (
    MappingIndex, compare_archives, compare_members, compare_trees, explain_line, file_diff,
)
from conftest import build_tsf

MAPPING = {
    "ip_addresses": {"10.0.0.5": "100.64.0.1", "8.8.8.8": "192.0.2.1"},
    "usernames": {"jdupont": "user001"},
    "fqdns": {"dc01.acme.local": "host001.anon.internal", "fw01": "host002"},
    "emails": {"j@acme.fr": "user001@host003.anon.internal"},
    "named_objects": {"Zone-A": "ZONE-0001", "web server prod": "ADDR-0002"},
    "serial_numbers": {"001901000123": "000000000001"},
}


class TestMappingIndex:
    def test_apply_rewrites_tokens(self):
        idx = MappingIndex(MAPPING)
        assert idx.apply("Zone-A peer 10.0.0.5 host DC01.ACME.LOCAL.") == \
            "ZONE-0001 peer 100.64.0.1 host host001.anon.internal."

    def test_apply_handles_multiword_and_cidr(self):
        idx = MappingIndex(MAPPING)
        assert idx.apply("web server prod 10.0.0.5/32") == "ADDR-0002 100.64.0.1/32"

    def test_apply_does_not_touch_substrings(self):
        idx = MappingIndex(MAPPING)
        assert idx.apply("10.0.0.50 Zone-AB fw01x") == "10.0.0.50 Zone-AB fw01x"

    def test_find_leaks(self):
        idx = MappingIndex(MAPPING)
        assert idx.find_leaks("Zone-A and zone-a and 10.0.0.5 x2 10.0.0.5") == {"Zone-A": 1, "10.0.0.5": 2}

    def test_find_leaks_is_case_insensitive_for_fqdns_only(self):
        idx = MappingIndex(MAPPING)
        assert idx.find_leaks("DC01.ACME.LOCAL zone-a") == {"dc01.acme.local": 1}

    def test_find_leaks_ignores_short_tokens(self):
        idx = MappingIndex({"named_objects": {"ab": "OBJ-1"}})
        assert idx.find_leaks("ab ab") == {}


class TestExplainLine:
    idx = MappingIndex(MAPPING)

    def test_mapping_driven_change_is_explained(self):
        assert explain_line("user 'jdupont' from 10.0.0.5", "user 'user001' from 100.64.0.1", self.idx)

    def test_unrelated_change_is_not(self):
        assert not explain_line("counter=5 peer 10.0.0.5", "counter=6 peer 100.64.0.1", self.idx)

    def test_deleted_text_is_not(self):
        assert not explain_line("peer 10.0.0.5 secret", "peer 100.64.0.1", self.idx)

    def test_span_fallback_handles_case_insensitive_fqdn(self):
        assert explain_line("to Dc01.Acme.Local now", "to host001.anon.internal now", self.idx)


@pytest.fixture
def anonymized(tmp_path):
    tsf = build_tsf(tmp_path)
    out = tmp_path / "out.tgz"
    _, mapping = anonymize_tsf(tsf, out, work_root=tmp_path / "work", keep_trees=True)
    return tsf, out, mapping, tmp_path / "work"


class TestHappyPath:
    def test_correct_anonymization_passes(self, anonymized):
        tsf, out, mapping, work = anonymized
        rep = compare_trees(work / "orig", work / "anon", mapping)
        s = rep.summary
        assert s["errors"] == 0, [(f.path, f.notes) for f in rep.files if f.status == "error"]
        assert s["unexplained_lines"] == 0, [(f.path, f.unexplained_sample) for f in rep.files]
        assert s["leaks_total"] == 0
        assert s["line_count_mismatches"] == 0
        assert s["timestamp_mismatches"] == 0
        assert s["numeric_mismatches"] == 0
        assert s["xml_checked"] == 1 and s["xml_structure_changed"] == 0
        assert s["anonymized"] == 5 and s["binary_identical"] == 2

    def test_binary_with_identifiers_is_a_warning_not_an_error(self, anonymized):
        _, _, mapping, work = anonymized
        rep = compare_trees(work / "orig", work / "anon", mapping)
        binf = next(f for f in rep.files if f.path.endswith("rule-hit-count.bin"))
        assert binf.status == "warning" and binf.binary_identical
        assert "Zone-Prod-DMZ" in binf.leaks and "172.16.4.9" in binf.leaks
        assert rep.summary["binary_files_with_identifiers"] == 2  # .bin + core.gz

    def test_archive_level_check_passes(self, anonymized):
        tsf, out, mapping, _ = anonymized
        arc = compare_members(tsf, out, mapping=mapping)
        assert arc["order_preserved"] and arc["metadata_differences"] == 0 and not arc["mismatches"]
        assert arc["members_renamed"] == 1

    def test_renamed_member_without_the_mapping_is_a_mismatch(self, anonymized):
        tsf, out, _, _ = anonymized
        assert compare_members(tsf, out)["mismatches"]

    def test_compare_archives_end_to_end(self, anonymized):
        tsf, out, mapping, _ = anonymized
        rep = compare_archives(tsf, out, mapping)
        assert rep.ok and rep.archive["order_preserved"]

    def test_without_mapping_changes_read_as_unexplained(self, anonymized):
        _, _, _, work = anonymized
        rep = compare_trees(work / "orig", work / "anon", {})
        assert rep.summary["unexplained_lines"] == rep.summary["changed_lines"] > 0


def _tamper(work: Path, rel: str, fn):
    p = work / "anon" / rel
    if rel.endswith(".gz"):
        data = gzip.decompress(p.read_bytes())
        with gzip.open(p, "wb") as f:
            f.write(fn(data))
    else:
        p.write_bytes(fn(p.read_bytes()))


class TestDetectsDamage:
    LOG = "var/log/pan/system.log"

    def test_dropped_line_is_an_error(self, anonymized):
        _, _, mapping, work = anonymized
        _tamper(work, self.LOG, lambda b: b.replace(b"\n", b"", 1))
        rep = compare_trees(work / "orig", work / "anon", mapping)
        f = next(f for f in rep.files if f.path == self.LOG)
        assert f.status == "error" and "line count" in f.notes[0]

    def test_altered_counter_is_unexplained(self, anonymized):
        _, _, mapping, work = anonymized
        _tamper(work, self.LOG, lambda b: b.replace(b"pid 4711", b"pid 4712"))
        rep = compare_trees(work / "orig", work / "anon", mapping)
        f = next(f for f in rep.files if f.path == self.LOG)
        assert f.unexplained_lines == 1 and f.status == "warning"
        assert rep.summary["numeric_mismatches"] == 0  # count equal, value differs — caught by explain

    def test_counts_cover_only_unexplained_lines(self, anonymized):
        _, _, mapping, work = anonymized
        rep = compare_trees(work / "orig", work / "anon", mapping)
        f = next(f for f in rep.files if f.path == self.LOG)
        assert f.unexplained_lines == 0 and f.timestamps_orig == 0 and f.numeric_orig == 0

    def test_surviving_identifier_is_an_error(self, anonymized):
        _, _, mapping, work = anonymized
        _tamper(work, self.LOG, lambda b: b + b"late line from 172.16.4.9\n")
        # also fix line count so the leak is what fails
        (work / "orig" / self.LOG).write_bytes((work / "orig" / self.LOG).read_bytes() + b"late line from x\n")
        rep = compare_trees(work / "orig", work / "anon", mapping)
        f = next(f for f in rep.files if f.path == self.LOG)
        assert f.leak_count == 1 and f.status == "error" and "172.16.4.9" in f.leaks

    def test_leak_in_rotated_gz_is_found(self, anonymized):
        _, _, mapping, work = anonymized
        rel = "var/log/pan/system.log.1.gz"
        _tamper(work, rel, lambda b: b.replace(b"100.64.", b"172.16.4.9 100.64.", 1))
        (work / "orig" / "var/log/pan/system.log.1.gz").write_bytes((work / "orig" / rel).read_bytes())
        rep = compare_trees(work / "orig", work / "anon", mapping)
        f = next(f for f in rep.files if f.path == rel)
        assert f.leak_count >= 1 and f.status == "error"

    def test_modified_binary_is_an_error(self, anonymized):
        _, _, mapping, work = anonymized
        _tamper(work, "var/log/pan/rule-hit-count.bin", lambda b: b + b"\x00")
        rep = compare_trees(work / "orig", work / "anon", mapping)
        f = next(f for f in rep.files if f.path.endswith(".bin"))
        assert f.status == "error" and f.binary_identical is False

    def test_missing_and_extra_files_are_errors(self, anonymized):
        _, _, mapping, work = anonymized
        (work / "anon" / "var/log/pan/untouched.txt").unlink()
        (work / "anon" / "var/log/pan/new.txt").write_text("x\n")
        rep = compare_trees(work / "orig", work / "anon", mapping)
        kinds = {f.path: f.kind for f in rep.files if f.status == "error"}
        assert kinds["var/log/pan/untouched.txt"] == "missing"
        assert kinds["var/log/pan/new.txt"] == "extra"

    def test_broken_xml_structure_is_an_error(self, anonymized):
        _, _, mapping, work = anonymized
        rel = "opt/pancfg/mgmt/saved-configs/running-config.xml"
        _tamper(work, rel, lambda b: b.replace(b"<action>allow</action>", b"<verdict>allow</verdict>"))
        rep = compare_trees(work / "orig", work / "anon", mapping)
        f = next(f for f in rep.files if f.path == rel)
        assert f.xml_structure == "changed" and f.status == "error"

    def test_removed_timestamp_is_a_warning(self, anonymized):
        _, _, mapping, work = anonymized
        _tamper(work, self.LOG, lambda b: b.replace(b"2026-04-07 10:00:06", b"xxxx-xx-xx xx:xx:xx"))
        rep = compare_trees(work / "orig", work / "anon", mapping)
        f = next(f for f in rep.files if f.path == self.LOG)
        assert f.timestamps_anon == f.timestamps_orig - 1 and f.status == "warning"

    def test_archive_reordered_or_retouched_is_reported(self, anonymized, tmp_path):
        tsf, out, _, work = anonymized
        import tarfile
        rebuilt = tmp_path / "rebuilt.tgz"
        with tarfile.open(rebuilt, "w:gz") as tar:
            tar.add(work / "anon", arcname=".")
        arc = compare_members(tsf, rebuilt)
        assert arc["mismatches"]


class TestFileDiff:
    def test_hunks_with_spans(self, anonymized):
        _, _, mapping, work = anonymized
        d = file_diff(work / "orig", work / "anon", "var/log/pan/system.log", mapping, context=1)
        assert d["changed_lines"] > 0 and d["hunks"]
        row = next(r for h in d["hunks"] for r in h["rows"] if r["changed"])
        assert row["explained"] is True and row["spans"]

    def test_window_mode(self, anonymized):
        _, _, mapping, work = anonymized
        d = file_diff(work / "orig", work / "anon", "var/log/pan/system.log", mapping,
                      start_line=2, window=3)
        assert [r["n"] for r in d["rows"]] == [2, 3, 4]

    def test_binary(self, anonymized):
        _, _, mapping, work = anonymized
        d = file_diff(work / "orig", work / "anon", "var/log/pan/rule-hit-count.bin", mapping)
        assert d["binary"] and d["identical"]

    def test_missing(self, anonymized):
        _, _, mapping, work = anonymized
        assert "error" in file_diff(work / "orig", work / "anon", "nope", mapping)

    def test_max_hunks_truncation_is_declared(self, tmp_path):
        (tmp_path / "o").mkdir(); (tmp_path / "a").mkdir()
        (tmp_path / "o/f").write_text("\n".join(f"peer 10.0.0.{i%250+1} x" if i % 2 else "same" for i in range(50)))
        (tmp_path / "a/f").write_text("\n".join(f"peer 100.64.0.{i%250+1} x" if i % 2 else "same" for i in range(50)))
        d = file_diff(tmp_path / "o", tmp_path / "a", "f", {}, context=0, max_hunks=3)
        assert d["truncated"] and len(d["hunks"]) == 3


def test_report_is_json_serialisable(anonymized):
    _, _, mapping, work = anonymized
    json.dumps(compare_trees(work / "orig", work / "anon", mapping).to_dict())


class TestDottedTokens:
    def test_key_followed_by_dotted_suffix_is_explained(self):
        idx = MappingIndex(MAPPING)
        assert idx.apply("Zone-A.x Zone-A. fw01.acme") == "ZONE-0001.x ZONE-0001. host002.acme"
        assert idx.apply("x.Zone-A") == "x.Zone-A"  # a label of a dotted name on the left: no
        assert explain_line("in Zone-A.x", "in ZONE-0001.x", idx)

    def test_fqdn_key_is_tried_whole_before_splitting(self):
        idx = MappingIndex(MAPPING)
        assert idx.apply("dc01.acme.local") == "host001.anon.internal"


class TestCollisionsAndLongLines:
    def test_key_that_is_also_a_fake_is_a_collision_not_a_leak(self):
        m = {"ip_addresses": {"100.64.0.3": "192.0.2.1", "10.0.0.1": "100.64.0.3"}}
        idx = MappingIndex(m)
        assert idx.collisions == ["100.64.0.3"]
        assert idx.find_leaks("peer 100.64.0.3") == {}
        assert idx.apply("peer 10.0.0.1") == "peer 100.64.0.3"

    def test_collisions_reach_the_summary(self, anonymized):
        _, _, mapping, work = anonymized
        rep = compare_trees(work / "orig", work / "anon", mapping)
        assert rep.summary["mapping_collisions"] == 0

    def test_long_line_is_diffed_by_token_quickly(self):
        import time
        from tsf_anonymizer.compare import _changed_spans
        a = " ".join(f"<entry name='obj{i}'><ip>10.0.0.{i%250}</ip></entry>" for i in range(1500))
        b = a.replace("10.0.0.7<", "100.64.0.1<")
        t0 = time.monotonic()
        spans = _changed_spans(a, b)
        assert time.monotonic() - t0 < 2.0
        assert spans and all(a[i1:i2] != b[j1:j2] for i1, i2, j1, j2 in spans)

    def test_huge_line_is_one_span(self):
        from tsf_anonymizer.compare import _changed_spans
        a = " ".join(f"t{i}" for i in range(5000)); b = a.replace("t7 ", "x ")
        assert _changed_spans(a, b) == [(0, len(a), 0, len(b))]


class TestNumericKeyBoundaries:
    idx = MappingIndex({"ip_addresses": {"203.0.113.184": "198.51.100.231"},
                        "serial_numbers": {"001901000456": "900000000001"}})

    def test_ip_inside_hyphenated_token_is_explained(self):
        assert self.idx.apply("connid: lr-203.0.113.184-2 x") == "connid: lr-198.51.100.231-2 x"
        assert explain_line("devid=triallr-203.0.113.184-1-def", "devid=triallr-198.51.100.231-1-def", self.idx)

    def test_serial_inside_underscored_token_is_explained(self):
        assert self.idx.apply("PA_001901000456_dt_12.1.4") == "PA_900000000001_dt_12.1.4"

    def test_ip_prefix_of_longer_ip_is_not_touched(self):
        assert self.idx.apply("203.0.113.1840 1.203.0.113.184") == "203.0.113.1840 1.203.0.113.184"

    def test_leak_scan_finds_ip_inside_token(self):
        assert self.idx.find_leaks("lr-203.0.113.184-2") == {"203.0.113.184": 1}


class TestBoundaryParity:
    def test_fqdn_after_at_sign_without_local_part_is_explained(self):
        idx = MappingIndex({"fqdns": {"mail.ru": "host008.anon.internal"}})
        assert explain_line("My World @Mail.Ru, et", "My World @host008.anon.internal, et", idx)

    def test_tag_and_attribute_contexts_are_not_leaks(self):
        idx = MappingIndex({"named_objects": {"connect-method": "OBJ-0001", "default-browser": "OBJ-0002"}})
        assert idx.find_leaks("<connect-method> x default-browser=0 </connect-method>") == {}
        assert idx.find_leaks("value connect-method here") == {"connect-method": 1}


def test_fqdn_after_a_dot_is_explained():
    idx = MappingIndex({"fqdns": {"home-lab.example": "host001.anon.internal"}})
    assert idx.apply("*.home-lab.example sub.home-lab.example") == "*.host001.anon.internal sub.host001.anon.internal"


def test_name_glued_to_a_timestamp_is_explained():
    idx = MappingIndex({"named_objects": {"GP_globalprotect_home-lab_example": "OBJ-0001"}})
    assert explain_line("Cert : GP_globalprotect_home-lab_example2026-04-05 09:38:00",
                        "Cert : OBJ-00012026-04-05 09:38:00", idx)


def test_the_parallel_pass_reports_exactly_what_the_sequential_one_does(tsf, tmp_path):
    """Spreading the per-file analysis over processes is a wall-clock change
    and nothing else: same reports, same order, same summary."""
    work = tmp_path / "work"
    _, mapping = anonymize_tsf(tsf, tmp_path / "out.tgz", work_root=work, keep_trees=True)
    one = compare_trees(work / "orig", work / "anon", mapping, workers=1)
    many = compare_trees(work / "orig", work / "anon", mapping, workers=3)

    assert many.to_dict() == one.to_dict()
    assert [f.path for f in many.files] == [f.path for f in one.files]


def test_apply_mirrors_the_pass_order_for_nested_keys():
    """An FQDN-mapped key with an IP inside it (address object named
    FW-Outside-10.30.135.97): the IP applied first would destroy the key."""
    from tsf_anonymizer.compare import MappingIndex, explain_line
    idx = MappingIndex({
        "fqdns": {"ocos-fw-outside-10.30.135.97": "host8964.anon.internal"},
        "ip_addresses": {"10.30.135.97": "100.64.1.78"},
    })
    o = "<description>OCOS-FW-Outside-10.30.135.97</description>"
    a = "<description>host8964.anon.internal</description>"
    assert explain_line(o, a, idx)


def test_compare_explains_the_vsys_glued_edl_name():
    from tsf_anonymizer.compare import MappingIndex, explain_line
    idx = MappingIndex({"named_objects": {"ThreatFeed-Partner": "OBJ-0001"}})
    assert explain_line("vsys1_ThreatFeed-Partner.ebl", "vsys1_OBJ-0001.ebl", idx)
