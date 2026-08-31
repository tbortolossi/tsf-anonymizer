"""The synthetic TSF is what the docs, the screenshots and a first try run on:
it must exercise every identifier class and come out of anonymize+verify clean."""

from __future__ import annotations

import json
import tarfile

from tsf_anonymizer import anonymize_tsf, compare_archives
from tsf_anonymizer.cli import main
from tsf_anonymizer.mock import DEVICE, DOMAIN, SERIAL, USERS, build_mock_tsf, default_mock_name


def _text_of(archive):
    import gzip
    out = []
    with tarfile.open(archive, "r:gz") as tar:
        for m in tar.getmembers():
            if not m.isfile() or m.name.endswith((".bin", "/wtmp")):
                continue  # binary payloads are copied through untouched, by design
            raw = tar.extractfile(m).read()
            if m.name.endswith(".gz"):
                raw = gzip.decompress(raw)
            out.append(raw.decode("utf-8", "replace"))
    return "\n".join(out)


def test_mock_is_deterministic(tmp_path):
    a = build_mock_tsf(tmp_path / "a.tgz", lines=50).read_bytes()
    b = build_mock_tsf(tmp_path / "b.tgz", lines=50).read_bytes()
    assert a == b
    assert build_mock_tsf(tmp_path / "c.tgz", lines=50, seed=8).read_bytes() != a


def test_mock_anonymizes_clean(tmp_path):
    src = build_mock_tsf(tmp_path / default_mock_name(), lines=60)
    out = tmp_path / "out.tgz"
    report, mapping = anonymize_tsf(src, out)
    assert report.errors == 0
    sizes = report.mapping_sizes
    for cls in ("ip_addresses", "usernames", "fqdns", "emails", "named_objects", "serial_numbers"):
        assert sizes[cls] > 0, cls
    text = _text_of(out)
    for ident in (DEVICE, DOMAIN, SERIAL, "CoreFirewallParis", *USERS, "Zone-Prod-DMZ", "172.16.4.1"):
        assert ident not in text, ident
    rep = compare_archives(src, out, mapping)
    assert rep.ok, [f.notes for f in rep.files if f.status == "error"]
    assert rep.summary["unexplained_lines"] == 0
    assert rep.summary["leaks_total"] == 0
    # The two binary payloads embed identifiers on purpose: the compare must say so.
    assert rep.summary["binary_files_with_identifiers"] == 2
    with tarfile.open(out) as tar:
        names = tar.getnames()
        assert f"./tmp/cli/techsupport_{DEVICE}_20260407_1000.txt" not in names
        assert tar.getmember("./opt/pancfg/mgmt/global/.hcr_metadata.json").mode == 0


def test_routing_fixtures_stay_coherent_after_anonymization(tmp_path):
    src = build_mock_tsf(tmp_path / "in.tgz", lines=30)
    out = tmp_path / "out.tgz"
    _, mapping = anonymize_tsf(src, out)
    ips = mapping["ip_addresses"]
    p24 = lambda ip: ip.rsplit(".", 1)[0]  # noqa: E731
    text = _text_of(out)
    # the OSPF-learned destination keeps one pseudonym across the RIB, the
    # LSDB, and both dated routed.log events (delete at 09:14, add at 09:17)
    dest = ips["10.99.5.0"]
    assert "10.99.5.0" not in text
    assert text.count(dest + "/24") >= 4
    # the nexthop stays inside the fake subnet of its interface...
    assert p24(ips["10.20.40.77"]) == p24(ips["10.20.40.1"])
    # ...the monitored IP shares the destination's fake /24...
    assert p24(ips["10.99.5.9"]) == p24(dest)
    # ...and the /16 static route still contains its learned /24
    assert ips["10.99.0.0"].split(".")[:2] == dest.split(".")[:2]


def test_mock_tsf_cli(tmp_path, capsys):
    out = tmp_path / "demo.tgz"
    assert main(["mock-tsf", "-o", str(out), "--lines", "20"]) == 0
    assert out.exists() and "mock TSF" in capsys.readouterr().out
    assert main(["anonymize", str(out), "--verify", "--report", str(tmp_path / "r.json")]) == 0
    assert json.loads((tmp_path / "r.json").read_text())["summary"]["errors"] == 0
