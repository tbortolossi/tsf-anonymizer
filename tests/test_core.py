"""Anonymizer tests — assert on the *output*: nothing identifying survives,
everything debugging depends on does."""

from __future__ import annotations

import gzip
import json
import tarfile

import pytest
from conftest import BINARY_PAYLOAD, CONFIG_XML, IDENTIFIERS, PRESERVED, read_member

from tsf_anonymizer.core import (
    Anonymizer,
    _is_panos_interface,
    anonymize_tsf,
    is_binary_file,
    mapping_sidecar_path,
    prescan_config_xml,
    process_file,
)


@pytest.fixture
def anon() -> Anonymizer:
    return Anonymizer()


class TestAnonIp:
    def test_private_ip_is_replaced_with_cgnat(self, anon):
        fake = anon.anon_ip("10.0.0.253")
        assert fake != "10.0.0.253" and fake.startswith("100.")
        assert 64 <= int(fake.split(".")[1]) <= 127

    def test_public_ip_is_replaced_with_test_net(self, anon):
        assert anon.anon_ip("8.8.8.8").split(".")[0] in {"192", "198", "203"}

    def test_same_ip_maps_to_same_fake(self, anon):
        assert anon.anon_ip("172.16.4.9") == anon.anon_ip("172.16.4.9")

    def test_different_ips_map_to_different_fakes(self, anon):
        assert anon.anon_ip("10.1.1.1") != anon.anon_ip("10.1.1.2")

    @pytest.mark.parametrize("keep", ["0.0.0.0", "255.255.255.0", "255.255.255.252",
                                      "127.0.0.1", "224.0.0.5", "169.254.1.1"])
    def test_masks_loopback_multicast_linklocal_preserved(self, anon, keep):
        assert anon.anon_ip(keep) == keep

    def test_cidr_suffix_is_preserved_in_text(self, anon):
        out = anon.anonymize_text("route 192.168.10.0/24 via 192.168.10.1")
        assert "/24" in out and "192.168.10.0" not in out and "192.168.10.1" not in out

    def test_version_like_dotted_quad_is_not_treated_as_ip(self, anon):
        assert anon.anonymize_text("build 10.1.2.3.4") == "build 10.1.2.3.4"


class TestSerials:
    def test_12_digit_serial_is_replaced(self, anon):
        assert "001901000123" not in anon.anonymize_text("serial 001901000123")

    def test_15_digit_vm_serial_is_replaced(self, anon):
        assert "007051000012345" not in anon.anonymize_text("serial 007051000012345")

    def test_epoch_millis_is_not_a_serial(self, anon):
        """13 digits is an epoch in ms — the old \\d{12,15} ate every one."""
        assert anon.anonymize_text("ts=1743840000123") == "ts=1743840000123"

    def test_fake_serial_keeps_length(self, anon):
        assert len(anon.anon_serial("007051000012345")) == 15


class TestFqdnAndEmail:
    def test_customer_fqdn_is_replaced(self, anon):
        assert anon.anon_fqdn("dc01.acme-corp.local").endswith(".anon.internal")

    @pytest.mark.parametrize("vendor", ["updates.paloaltonetworks.com", "0.pool.ntp.org"])
    def test_vendor_domains_are_preserved(self, anon, vendor):
        assert anon.anon_fqdn(vendor) == vendor

    def test_email_domain_reuses_the_fqdn_mapping(self, anon):
        fake = anon.anon_email("jean", "acme-corp.fr")
        assert fake.split("@")[1] == anon.fqdn_map["acme-corp.fr"]


class TestNamedObjects:
    def test_object_gets_a_categorised_placeholder(self, anon):
        assert anon.register_named_object("Zone-Prod-DMZ", "zone").startswith("ZONE-")

    @pytest.mark.parametrize("intf", ["ethernet1/1", "ethernet1/1.100", "ae1", "tunnel.1", "hsci"])
    def test_panos_interface_names_are_preserved(self, anon, intf):
        assert _is_panos_interface(intf)
        assert anon.register_named_object(intf, "intf") == intf

    def test_multiword_object_is_replaced_as_a_whole(self, anon):
        anon.register_named_object("web server prod", "addr")
        anon.build_patterns()
        out = anon.anonymize_text("hit web server prod today")
        assert "web server prod" not in out and "ADDR-0001" in out

    def test_anonymize_text_without_build_patterns_builds_them(self, anon):
        anon.register_named_object("X-Y", "zone")
        assert anon.anonymize_text("X-Y") == "ZONE-0001"  # patterns compiled lazily


class TestFromMapping:
    def test_seeded_anonymizer_reuses_pseudonyms_and_continues_numbering(self):
        a = Anonymizer()
        a.anon_ip("10.0.0.1"); a.register_named_object("Zone-A", "zone"); a.anon_user("bob")
        b = Anonymizer.from_mapping(json.loads(json.dumps(a.get_mapping())))
        assert b.anon_ip("10.0.0.1") == a.ip_map["10.0.0.1"]
        assert b.anon_ip("10.0.0.2") != a.ip_map["10.0.0.1"]
        assert b.register_named_object("Zone-B", "zone") == "ZONE-0002"
        assert b.anon_user("alice") == "user002"


class TestProcessFile:
    def test_crlf_and_latin1_bytes_survive(self, tmp_path, anon):
        """Byte-exact round trip: only identifiers change."""
        raw = b"peer 10.0.0.5 caf\xe9\r\nnext line\r\n"
        p = tmp_path / "x.log"
        p.write_bytes(raw)
        assert process_file(p, anon).action == "modified"
        out = p.read_bytes()
        assert b"10.0.0.5" not in out
        assert b"caf\xe9\r\nnext line\r\n" in out

    def test_binary_file_is_skipped(self, tmp_path, anon):
        p = tmp_path / "x.dat"
        p.write_bytes(BINARY_PAYLOAD)
        assert process_file(p, anon).action == "binary"
        assert p.read_bytes() == BINARY_PAYLOAD

    def test_gz_text_is_anonymized_and_stays_gzipped(self, tmp_path, anon):
        p = tmp_path / "x.log.gz"
        with gzip.open(p, "wb") as f:
            f.write(b"peer 10.0.0.5\n")
        assert process_file(p, anon).action == "modified"
        assert b"10.0.0.5" not in gzip.decompress(p.read_bytes())

    def test_gz_binary_is_left_alone(self, tmp_path, anon):
        p = tmp_path / "core.gz"
        with gzip.open(p, "wb") as f:
            f.write(BINARY_PAYLOAD)
        before = p.read_bytes()
        assert process_file(p, anon).action == "gz_binary"
        assert p.read_bytes() == before

    def test_replacement_counts_are_reported(self, tmp_path, anon):
        p = tmp_path / "x.log"
        p.write_bytes(b"10.0.0.1 10.0.0.2 mail a@b.example.org\n")
        out = process_file(p, anon)
        assert out.replacements["ip_addresses"] == 2
        assert out.replacements["emails"] == 1

    def test_unreadable_extension_is_binary(self, tmp_path):
        p = tmp_path / "x.PNG"
        p.write_bytes(b"plain text really")
        assert is_binary_file(p)


class TestPrescan:
    @pytest.fixture
    def scanned(self, tmp_path):
        p = tmp_path / "running-config.xml"
        p.write_text(CONFIG_XML)
        anon = Anonymizer()
        prescan_config_xml(p, anon)
        return anon

    def test_named_entries_are_registered_with_category(self, scanned):
        assert scanned.named_obj_map["Zone-Prod-DMZ"].startswith("ZONE-")
        assert scanned.named_obj_map["Allow-Compta-to-DMZ"].startswith("RULE-")
        assert scanned.named_obj_map["GW-Paris-Primary"].startswith("GW-")

    def test_builtin_entries_are_not_registered(self, scanned):
        assert "trust" not in scanned.named_obj_map and "vsys1" not in scanned.named_obj_map

    def test_hostname_and_serial_are_registered(self, scanned):
        assert "fw-paris-01" in scanned.fqdn_map
        assert "001901000123" in scanned.serial_map

    def test_ldap_dn_and_cert_cn_are_registered(self, scanned):
        assert "acme-corp.local" in scanned.fqdn_map
        assert "vpn.acme-corp.fr" in scanned.fqdn_map

    def test_ntp_vendor_host_is_not_registered(self, scanned):
        assert "0.pool.ntp.org" not in scanned.fqdn_map

    def test_ip_in_address_field_is_not_registered_as_fqdn(self, tmp_path):
        p = tmp_path / "c.xml"
        p.write_text("<c><server><entry name='x'><address>10.0.0.9</address></entry></server></c>")
        anon = Anonymizer(); prescan_config_xml(p, anon)
        assert "10.0.0.9" not in anon.fqdn_map

    def test_unparseable_xml_does_not_raise(self, tmp_path):
        p = tmp_path / "c.xml"
        p.write_text("<not xml")
        prescan_config_xml(p, Anonymizer())


class TestAnonymizeTsf:
    @pytest.fixture
    def output(self, tmp_path, tsf):
        out = tmp_path / "out.tgz"
        report, mapping = anonymize_tsf(tsf, out)
        return out, report, mapping

    @pytest.mark.parametrize("identifier", IDENTIFIERS)
    def test_identifier_does_not_survive_in_logs_or_config(self, output, identifier):
        out, _, _ = output
        for member in ("./var/log/pan/system.log", "./opt/pancfg/mgmt/saved-configs/running-config.xml"):
            assert identifier.encode() not in read_member(out, member)

    @pytest.mark.parametrize("identifier", IDENTIFIERS)
    def test_rotated_gz_log_is_anonymized_too(self, output, identifier):
        out, _, _ = output
        assert identifier.encode() not in gzip.decompress(read_member(out, "./var/log/pan/system.log.1.gz"))

    @pytest.mark.parametrize("keep", PRESERVED)
    def test_debugging_value_survives(self, output, keep):
        out, _, _ = output
        assert keep.encode() in read_member(out, "./var/log/pan/system.log")

    def test_latin1_byte_and_crlf_survive(self, output):
        out, _, _ = output
        log = read_member(out, "./var/log/pan/system.log")
        assert b"caf\xe9" in log and b"show clock\r\n" in log

    def test_line_count_is_preserved(self, output, tsf):
        out, _, _ = output
        member = "./var/log/pan/system.log"
        assert read_member(out, member).count(b"\n") == read_member(tsf, member).count(b"\n")

    def test_binary_files_are_byte_identical(self, output):
        out, _, _ = output
        assert read_member(out, "./var/log/pan/rule-hit-count.bin") == BINARY_PAYLOAD
        assert gzip.decompress(read_member(out, "./var/log/pan/core.1.gz")) == BINARY_PAYLOAD

    def test_member_order_and_metadata_are_preserved(self, output, tsf):
        out, _, mapping = output
        from tsf_anonymizer.compare import MappingIndex
        idx = MappingIndex(mapping)
        with tarfile.open(tsf) as a, tarfile.open(out) as b:
            ma, mb = a.getmembers(), b.getmembers()
        # Names are preserved *through the mapping*: a member named after the
        # device comes out renamed, exactly as the text would.
        from tsf_anonymizer.core import mapped_member_name
        assert [mapped_member_name(idx.apply, m.name) for m in ma] == [m.name for m in mb]
        for x, y in zip(ma, mb, strict=True):
            assert (x.mode, x.uid, x.gid, x.uname, x.mtime, x.type) == (y.mode, y.uid, y.gid, y.uname, y.mtime, y.type)

    def test_mode_0000_file_is_anonymized_and_keeps_its_mode(self, output):
        """The working copy needs u+rw to be processed; the archive must not."""
        out, _, _ = output
        member = "./opt/pancfg/mgmt/global/.hcr_metadata.json"
        assert b"172.16.4.9" not in read_member(out, member)
        with tarfile.open(out) as tar:
            assert tar.getmember(member).mode == 0o000

    def test_hostname_absent_from_the_config_is_not_redacted(self, output):
        """Documented limitation, asserted so it stays a known one."""
        out, _, _ = output
        assert b"undeclared-host" in read_member(out, "./var/log/pan/system.log")

    def test_mapping_sidecar_is_written_and_matches_returned_mapping(self, output):
        out, _, mapping = output
        side = json.loads(mapping_sidecar_path(out).read_text())
        assert side == mapping
        assert side["named_objects"]["Zone-Prod-DMZ"].startswith("ZONE-")

    def test_report_counts(self, output):
        _, report, _ = output
        assert report.files_total == 8
        assert report.modified == 5          # log, gz log, config, mode-0000 json, techsupport txt
        assert report.members_renamed == 1   # techsupport_<devicename>_<date>.txt
        assert report.binary == 2            # .bin + core.gz
        assert report.unchanged == 1
        assert report.errors == 0
        assert report.replacements["ip_addresses"] > 0

    def test_mapping_only_writes_no_archive(self, tmp_path, tsf):
        out = tmp_path / "m.tgz"
        _, mapping = anonymize_tsf(tsf, out, mapping_only=True)
        assert not out.exists() and mapping["named_objects"]

    def test_seeded_run_is_consistent(self, tmp_path, tsf, output):
        _, _, mapping = output
        out2 = tmp_path / "out2.tgz"
        _, mapping2 = anonymize_tsf(tsf, out2, seed_mapping=mapping)
        assert mapping2 == mapping
        assert read_member(out2, "./var/log/pan/system.log") == read_member(output[0], "./var/log/pan/system.log")

    def test_kept_trees(self, tmp_path, tsf):
        root = tmp_path / "work"
        anonymize_tsf(tsf, tmp_path / "o.tgz", work_root=root, keep_trees=True)
        assert (root / "orig/var/log/pan/system.log").is_file()
        assert (root / "anon/var/log/pan/system.log").is_file()

    def test_absolute_and_traversal_members_do_not_escape(self, tmp_path):
        src = tmp_path / "system.log"; src.write_text("peer 10.0.0.253\n")
        archive = tmp_path / "evil.tgz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(src, arcname="/system.log")
            tar.add(src, arcname="../escape.log")
        out = tmp_path / "evil-out.tgz"
        report, _ = anonymize_tsf(archive, out)
        assert report.members_skipped == 1
        with tarfile.open(out) as tar:
            names = tar.getnames()
        assert names == ["system.log"]
        assert not (tmp_path.parent / "escape.log").exists()


class TestTrieRegex:
    def test_longest_key_wins(self, anon):
        anon.register_named_object("GW-Paris", "gw")
        anon.register_named_object("GW-Paris-Primary", "gw")
        anon.build_patterns()
        out = anon.anonymize_text("GW-Paris-Primary and GW-Paris")
        assert out == "GW-0002 and GW-0001"

    def test_not_inside_a_longer_word_or_hyphenated_compound(self, anon):
        anon.register_named_object("web", "addr")
        anon.build_patterns()
        assert anon.anonymize_text("web webserver web-server-1 x.web web.") == \
            "ADDR-0001 webserver web-server-1 x.web ADDR-0001."

    def test_special_characters_in_names(self, anon):
        anon.register_named_object("Rule (test) [v2]", "rule")
        anon.build_patterns()
        assert anon.anonymize_text("hit Rule (test) [v2] now") == "hit RULE-0001 now"

    def test_thousands_of_keys_are_a_single_fast_pass(self, anon):
        import time
        for i in range(5000):
            anon.register_named_object(f"Object-Name-{i:05d}", "addr")
        anon.build_patterns()
        text = " ".join(f"token{i} Object-Name-{i % 5000:05d}" for i in range(50_000))
        t0 = time.monotonic()
        out = anon.anonymize_text(text)
        assert time.monotonic() - t0 < 5.0
        assert "Object-Name-" not in out


class TestRealTsfLessons:
    """Each of these was found by the compare mode on a real 155 MB TSF."""

    def test_object_named_like_an_xml_tag_does_not_rewrite_tags(self, anon):
        for name in ("enabled", "bgp", "Apple", "name"):
            anon.register_named_object(name, "obj")
        anon.build_patterns()
        xml = '<bgp><enabled>yes</enabled><entry name="Apple"><member>bgp</member></entry></bgp>'
        out = anon.anonymize_text(xml)
        assert out.startswith("<bgp><enabled>yes</enabled>") and out.endswith("</entry></bgp>")
        assert 'name="OBJ-' in out and "<member>OBJ-" in out

    def test_predefined_subtree_and_content_files_are_not_prescanned(self, tmp_path):
        (tmp_path / "running-config.xml").write_text(
            "<config><predefined><application><entry name='Apple'/></application></predefined>"
            "<vsys><entry name='vsys1'><zone><entry name='Zone-X'/></zone></entry></vsys></config>")
        (tmp_path / "updates").mkdir()
        (tmp_path / "updates/global.xml").write_text("<c><application><entry name='Linux'/></application></c>")
        (tmp_path / "predefined.xml").write_text("<c><application><entry name='bgp'/></application></c>")
        anon = Anonymizer()
        from tsf_anonymizer.core import prescan_tree
        prescan_tree(tmp_path, anon)
        assert set(anon.named_obj_map) == {"Zone-X"}

    def test_a_fake_is_never_re_anonymized(self, anon):
        anon.register_named_object("jdupont", "user")
        anon.build_patterns()
        out = anon.anonymize_text("login for user 'jdupont' ok")
        assert out == "login for user 'USR-0001' ok"
        assert anon.user_map == {}

    def test_ca_org_names_in_certificates_are_not_fqdns(self, tmp_path):
        p = tmp_path / "c.xml"
        p.write_text("<c><certificate><entry name='x'><subject>C = US, O = GeoTrust Inc., "
                     "OU = Network Solutions L.L.C., CN = vpn.acme.fr</subject></entry></certificate></c>")
        anon = Anonymizer(); prescan_config_xml(p, anon)
        assert set(anon.fqdn_map) == {"vpn.acme.fr", "acme.fr"}  # CN + its apex

    def test_admin_contact_is_anonymized(self, tmp_path):
        p = tmp_path / "c.xml"
        p.write_text("<c><system><contact>Thomas</contact></system></c>")
        anon = Anonymizer(); prescan_config_xml(p, anon); anon.build_patterns()
        assert "Thomas" not in anon.anonymize_text("<contact>Thomas</contact> by Thomas")

    def test_zero_padded_counters_are_not_serials(self, anon):
        assert anon.anonymize_text("pkts 000000024894 000000000000") == "pkts 000000024894 000000000000"

    def test_12_digit_ids_not_starting_with_zero_are_not_serials(self, anon):
        assert anon.anonymize_text("id 486712289187 x 111111111111") == "id 486712289187 x 111111111111"

    def test_config_global_catalog_is_not_prescanned(self, tmp_path):
        (tmp_path / "candidatecfg.1.xml").write_text(
            "<config><global><application><entry name='Apple'/></application>"
            "<iot-definitions><attribute><entry name='Gosund'/></attribute></iot-definitions></global>"
            "<devices><entry name='localhost.localdomain'><vsys><entry name='vsys1'>"
            "<address><entry name='SRV-X'/></address></entry></vsys></entry></devices></config>")
        anon = Anonymizer()
        from tsf_anonymizer.core import prescan_tree
        prescan_tree(tmp_path, anon)
        assert set(anon.named_obj_map) == {"SRV-X"}

    def test_declared_serial_is_replaced_whatever_its_shape(self, anon):
        anon.anon_serial("000000000021"); anon.build_patterns()
        out = anon.anonymize_text("device 000000000021 ok")
        assert "000000000021" not in out and out.startswith("device 9")

    def test_fake_serial_cannot_collide_with_a_real_one(self, anon):
        assert anon.anon_serial("001901000123").startswith("9")
        assert len(anon.anon_serial("007051000012345")) == 15

    def test_fake_ip_skips_an_original_we_already_know(self, anon):
        anon.anon_ip("100.64.0.1")            # the customer uses our fake range
        fake = anon.anon_ip("10.0.0.9")        # first private fake would be 100.64.0.1
        assert fake != "100.64.0.1"


class TestRealTsfLessonsRound2:
    def test_url_and_path_contexts_are_rewritten_but_tags_are_not(self, anon):
        anon.register_fqdn("vpn.acme.fr")
        anon.register_named_object("Zone-A", "zone")
        anon.build_patterns()
        out = anon.anonymize_text("https://vpn.acme.fr/x /etc/Zone-A/y </Zone-A> <Zone-A> vpn.acme.fr.csr")
        assert out == "https://host001.anon.internal/x /etc/ZONE-0001/y </Zone-A> <Zone-A> host001.anon.internal.csr"

    def test_url_scheme_is_never_rewritten(self, anon):
        anon.register_named_object("MyProto", "obj")
        anon.build_patterns()
        assert anon.anonymize_text("MyProto://x and MyProto") == "MyProto://x and OBJ-0001"

    def test_ip_at_end_of_sentence_is_replaced(self, anon):
        out = anon.anonymize_text("peer 10.0.0.5. next 10.0.0.6.7.8")
        assert "10.0.0.5" not in out and "10.0.0.6.7.8" in out

    def test_vocabulary_entries_are_not_registered(self, tmp_path):
        p = tmp_path / "c.xml"
        p.write_text("<c><devices><vsys><zone><entry name='LAN'/><entry name='lan2'/></zone>"
                     "<profiles><virus><entry name='AV-Prod'><decoder><entry name='http'/><entry name='smtp'/></decoder></entry></virus>"
                     "<spyware><entry name='SP'><botnet-domains><dns-security-categories><entry name='pan-dns-sec-malware'/></dns-security-categories></botnet-domains></entry></spyware></profiles>"
                     "<application><entry name='QUIC'/></application>"
                     "<certificate><entry name='pan_devicetelem'/><entry name='Cert-GP'/></certificate>"
                     "<external-list><entry name='panw-known-ip-list'/><entry name='EDL-Blocklist'/></external-list>"
                     "</vsys></devices></c>")
        anon = Anonymizer(); prescan_config_xml(p, anon)
        # "lan2" is a zone: an identity container keeps lowercase names.
        assert set(anon.named_obj_map) == {"LAN", "lan2", "AV-Prod", "SP", "Cert-GP", "EDL-Blocklist"}

    def test_object_named_like_a_known_fqdn_gets_the_fqdn_pseudonym(self, anon):
        anon.register_fqdn("igw.acme.fr")
        anon.register_named_object("igw.acme.fr", "obj")     # certificate entry
        anon.build_patterns()
        out = anon.anonymize_text("cert igw.acme.fr file igw.acme.fr.csr")
        assert out == "cert host001.anon.internal file host001.anon.internal.csr"
        assert "igw.acme.fr" not in anon.named_obj_map


class TestRealTsfLessonsRound3:
    def test_ip_named_entry_is_owned_by_the_ip_pass(self, tmp_path, anon):
        p = tmp_path / "c.xml"
        p.write_text("<c><devices><vsys><address><entry name='10.0.0.254/24'/><entry name='10.0.0.102'/>"
                     "<entry name='SRV-1'/></address></vsys></devices></c>")
        prescan_config_xml(p, anon); anon.build_patterns()
        assert set(anon.named_obj_map) == {"SRV-1"}
        out = anon.anonymize_text("<entry name='10.0.0.254/24'/> if 10.0.0.254/24 file 10.0.0.102-32823.pcap")
        assert "10.0.0.254" not in out and "10.0.0.102" not in out
        assert out.count(anon.ip_map["10.0.0.254"]) == 2 and "/24" in out and "-32823.pcap" in out

    def test_fqdn_named_entry_is_a_fqdn(self, tmp_path, anon):
        p = tmp_path / "c.xml"
        p.write_text("<c><devices><vsys><address><entry name='web.acme.fr'/></address></vsys></devices></c>")
        prescan_config_xml(p, anon)
        assert "web.acme.fr" in anon.fqdn_map and not anon.named_obj_map

    def test_lowercase_admin_and_user_entries_are_identities(self, tmp_path, anon):
        p = tmp_path / "c.xml"
        p.write_text("<c><mgt-config><users><entry name='jmartin'/></users></mgt-config>"
                     "<devices><vsys><profiles><virus><entry name='av'><decoder><entry name='http'/></decoder>"
                     "</entry></virus></profiles></vsys></devices></c>")
        prescan_config_xml(p, anon)
        assert "jmartin" in anon.named_obj_map and "http" not in anon.named_obj_map

    def test_usernames_found_in_logs_are_replaced_everywhere(self, tmp_path):
        from tsf_anonymizer.core import prescan_text_identities
        (tmp_path / "a.log").write_text('audit UID="jdupont" (jdupont) exe=/usr/bin/su\n')
        (tmp_path / "b.log").write_text("authenticated for user 'jdupont' ok; mail j@acme.fr\n")
        anon = Anonymizer()
        prescan_text_identities(tmp_path, anon)
        anon.build_patterns()
        assert anon.user_map == {"jdupont": "user001"}
        out = anon.anonymize_text((tmp_path / "a.log").read_text())
        assert out == 'audit UID="user001" (user001) exe=/usr/bin/su\n'
        assert "acme.fr" in anon.fqdn_map   # the e-mail domain was discovered too

    def test_system_accounts_are_not_usernames(self, anon):
        assert anon.anonymize_text("for user 'pan_devicetelem'") == "for user 'pan_devicetelem'"

    def test_patterns_rebuild_when_a_table_grows_mid_run(self, anon):
        anon.build_patterns()
        anon.anonymize_text("mail from bob@mail-corp.ru")       # registers the domain
        out = anon.anonymize_text("bare mail-corp.ru here")      # next file: bare occurrence
        assert "mail-corp.ru" not in out


class TestRealTsfLessonsRound4:
    def test_gp_app_config_setting_names_are_vocabulary(self, tmp_path, anon):
        p = tmp_path / "c.xml"
        p.write_text("<c><devices><vsys><global-protect><global-protect-portal><entry name='GP-Portal'>"
                     "<client-config><configs><entry name='Cfg-1'><gp-app-config><config>"
                     "<entry name='connect-method'><member>on-demand</member></entry>"
                     "<entry name='default-browser'><member>no</member></entry>"
                     "</config></gp-app-config></entry></configs></client-config></entry>"
                     "</global-protect-portal></global-protect></vsys></devices></c>")
        prescan_config_xml(p, anon)
        assert set(anon.named_obj_map) == {"GP-Portal", "Cfg-1"}

    def test_busybox_datetime_is_not_a_serial(self, anon):
        assert anon.anonymize_text("datetime-busybox: 040509422026.34") == "datetime-busybox: 040509422026.34"
        assert "001901000123" not in anon.anonymize_text("serial 001901000123")


class TestRealTsfLessonsRound5:
    def test_parent_domains_are_registered_and_wildcards_rewritten(self, anon):
        anon.register_fqdn("igw.home-lab.example")
        assert "home-lab.example" in anon.fqdn_map and "com" not in anon.fqdn_map
        anon.build_patterns()
        out = anon.anonymize_text("https://home-lab.example/x <member>*.home-lab.example</member> igw.home-lab.example sub.home-lab.example")
        assert "home-lab" not in out
        assert out.count(anon.fqdn_map["home-lab.example"]) == 3   # apex, *.apex, sub.apex
        assert anon.fqdn_map["igw.home-lab.example"] in out

    def test_dn_stopword_parent_is_not_registered(self, anon):
        anon.register_fqdn("dc01.acme-corp.local")
        assert "acme-corp.local" in anon.fqdn_map and "local" not in anon.fqdn_map

    def test_dhcp_hostname_phrase_is_discovered(self, tmp_path):
        from tsf_anonymizer.core import prescan_text_identities
        (tmp_path / "pan_dhcpd.log").write_text(
            "mac 9a:5d:df:33:13:29 - hostname Tab-S6-Lite-de-Thomas, interface ethernet1/8.100\n"
            'audit hostname=? addr=? terminal=?\n')
        anon = Anonymizer(); prescan_text_identities(tmp_path, anon); anon.build_patterns()
        assert "tab-s6-lite-de-thomas" in anon.fqdn_map
        out = anon.anonymize_text((tmp_path / "pan_dhcpd.log").read_text())
        assert "Thomas" not in out and "hostname=? addr=?" in out and "ethernet1/8.100" in out


class TestHostnamePhraseIsStrict:
    def test_prose_and_next_line_are_not_hostnames(self, tmp_path):
        from tsf_anonymizer.core import prescan_text_identities
        (tmp_path / "x.log").write_text(
            "set the hostname to something\nhostname of the box\n"
            "-rw-r--r--. 1 root root 12 2026-03-01 hostname\ndrwxr-xr-x. 2 root root 4096 252.acl\n"
            "hostnamectl status\nhostname: fw-paris-01\nhostname=\"lab-fw2\"\n"
            "mac aa:bb - hostname iphone, interface ethernet1/1\n")
        anon = Anonymizer(); prescan_text_identities(tmp_path, anon)
        assert set(anon.fqdn_map) == {"fw-paris-01", "lab-fw2"}

    def test_file_names_never_become_domains(self, anon):
        anon.register_fqdn("hostname.conf.5.gz")
        assert not any(k.endswith(".gz") or k.startswith(".") for k in anon.fqdn_map if k != "hostname.conf.5.gz")
        anon.register_fqdn("2f063b1936a14a2687401ccea439ed70-0000000000000001-00064d5ebb4c4413.journal")
        assert "journal" not in anon.fqdn_map

    def test_hyphenated_compound_is_not_a_fqdn_context(self, anon):
        anon.register_fqdn("to.example-corp.fr")  # registers "example-corp.fr" too; never "to"
        anon.build_patterns()
        assert "to" not in anon.fqdn_map
        anon.fqdn_map["to"] = "host099"; anon.build_patterns()   # even if it were a key…
        assert anon.anonymize_text("<equal-to>x</equal-to> link-state") == "<equal-to>x</equal-to> link-state"


def test_object_glued_to_a_timestamp_is_still_replaced():
    """md_out.log: 'SSL Server Cert : GP_globalprotect_home-lab_example2026-04-05 09:38:00'."""
    anon = Anonymizer()
    anon.register_named_object("GP_globalprotect_home-lab_example", "obj")
    anon.build_patterns()
    out = anon.anonymize_text("Cert : GP_globalprotect_home-lab_example2026-04-05 09:38:00")
    assert "home-lab" not in out and "2026-04-05 09:38:00" in out
    # but a name glued to arbitrary digits is a different token and stays
    assert anon.anonymize_text("GP_globalprotect_home-lab_example42") == "GP_globalprotect_home-lab_example42"


def test_every_phase_reports_how_far_it_is(tsf, tmp_path):
    """extract, copy and repack must count, not just start and stop.

    On a real TSF each of them runs for minutes; a bar that only knows 0/1 then
    1/1 sits at 0 % the whole time and cannot be told from a hung run.
    """
    seen = []
    anonymize_tsf(tsf, tmp_path / "out.tgz",
                  progress=lambda phase, done, total, msg: seen.append((phase, done, total)))

    for phase in ("extract", "copy", "repack"):
        steps = [(d, t) for p, d, t in seen if p == phase]
        assert steps, f"{phase} reported nothing"
        assert max(t for _, t in steps) > 1, f"{phase} still reports a 0/1 → 1/1 bar"
        assert all(0 <= d <= t for d, t in steps), f"{phase} reported an impossible position"
        assert steps[-1][0] == steps[-1][1], f"{phase} did not end full"


class TestDetectThenFreeze:
    """The rewrite runs with frozen tables: everything is discovered before
    anything is rewritten, which is what makes the rewrite a pure function
    and the process pool safe."""

    def test_parallel_run_is_identical_to_sequential(self, tmp_path, tsf):
        out_seq, out_par = tmp_path / "seq.tgz", tmp_path / "par.tgz"
        _, m_seq = anonymize_tsf(tsf, out_seq, workers=1)
        _, m_par = anonymize_tsf(tsf, out_par, workers=2)
        assert m_seq == m_par
        with tarfile.open(out_seq) as t1, tarfile.open(out_par) as t2:
            names1 = [m.name for m in t1.getmembers()]
            assert names1 == [m.name for m in t2.getmembers()]
            for name in names1:
                a, b = t1.getmember(name), t2.getmember(name)
                if not a.isfile():
                    continue
                p1, p2 = t1.extractfile(a).read(), t2.extractfile(b).read()
                if name.endswith(".gz"):
                    # gzip stamps the write time in its header; the payload
                    # is what must match.
                    try:
                        p1, p2 = gzip.decompress(p1), gzip.decompress(p2)
                    except OSError:
                        pass
                assert p1 == p2, name

    def test_rewrite_allocates_nothing_after_the_prescan(self, tmp_path, tsf):
        report, full_mapping = anonymize_tsf(tsf, tmp_path / "out.tgz")
        _, prescan_mapping = anonymize_tsf(tsf, None, mapping_only=True)
        assert prescan_mapping == full_mapping
        assert not any(f.warnings for f in report.files)


class TestSalvagePrescan:
    """A config that fails ET.parse used to register nothing — its identifiers
    went out un-anonymized, invisible to the compare mode. The pull-parser
    salvage reads the parseable prefix with parent context intact."""

    def test_truncated_config_still_registers_its_objects(self, tmp_path):
        broken = CONFIG_XML[:CONFIG_XML.rindex("<certificate")]
        p = tmp_path / "failed_candidatecfg.xml"
        p.write_text(broken)
        anon = Anonymizer()
        prescan_config_xml(p, anon)
        assert "Zone-Prod-DMZ" in anon.named_obj_map
        assert "GW-Paris-Primary" in anon.named_obj_map
        assert "acme-corp.local" in anon.fqdn_map

    def test_salvaged_prefix_still_skips_the_vendor_catalog(self, tmp_path):
        broken = (
            "<config>"
            "<predefined><application><entry name='vendor-app-x'/></application></predefined>"
            "<global><application><entry name='vendor-app-y'/></application></global>"
            "<devices><entry name='localhost.localdomain'><vsys><entry name='vsys1'>"
            "<zone><entry name='Zone-Cut-Test'/></zone>"
        )
        p = tmp_path / "failed_candidatecfg.xml"
        p.write_text(broken)
        anon = Anonymizer()
        prescan_config_xml(p, anon)
        assert "Zone-Cut-Test" in anon.named_obj_map
        assert "vendor-app-x" not in anon.named_obj_map
        assert "vendor-app-y" not in anon.named_obj_map

    def test_empty_xml_registers_nothing_and_does_not_raise(self, tmp_path):
        p = tmp_path / "dp-config.xml"
        p.write_text("")
        anon = Anonymizer()
        prescan_config_xml(p, anon)
        assert not anon.named_obj_map


class TestRealTsfWarningFixes:
    """Each of these reproduces a warning family from a real 2026-08-31 run:
    thousands of 'changed beyond the mapping' lines, all traced to mapping
    entries that could never fire (or should never have existed)."""

    def test_logdb_filename_sequence_is_not_a_serial(self, anon):
        anon.build_patterns()
        line = "dst_profile : /opt/pancfg/mgmt/logdb/traffic/1/20260225/pan.000100628656.log"
        assert anon.anonymize_text(line) == line

    def test_declared_serial_after_a_dot_is_a_filename_not_a_serial(self, anon):
        anon.anon_serial("001901000123")
        anon.build_patterns()
        assert "9" + "0" * 8 not in anon.anonymize_text("kept: pan.001901000123.log")
        assert "001901000123" not in anon.anonymize_text("serial: 001901000123")

    def test_domain_backslash_user_entry_is_two_identities(self, tmp_path, anon):
        xml = ('<config><devices><users>'
               '<entry name="acme\\jdupont" id="21621"/>'
               '</users></devices></config>')
        p = tmp_path / "userinfo.xml"
        p.write_text(xml)
        prescan_config_xml(p, anon)
        anon.build_patterns()
        out = anon.anonymize_text("login acme\\jdupont ok; portal acme; user 'jdupont'")
        assert "acme" not in out and "jdupont" not in out
        assert "\\" in out  # the DOMAIN\\user shape survives, the identities do not
        assert not any("\\" in k for k in anon.named_obj_map)

    def test_stopword_domain_registers_only_the_user(self, tmp_path, anon):
        xml = '<config><devices><users><entry name="corp\\jdoe"/></users></devices></config>'
        p = tmp_path / "userinfo.xml"
        p.write_text(xml)
        prescan_config_xml(p, anon)
        anon.build_patterns()
        out = anon.anonymize_text("login corp\\jdoe")
        assert "jdoe" not in out and "corp\\" in out

    def test_object_embedding_a_fqdn_is_not_a_dead_mapping_entry(self, anon):
        anon.register_fqdn("enloe")
        anon.register_named_object("Enloe Domain controllers", "srv-prof")
        anon.build_patterns()
        out = anon.anonymize_text("server profile 'Enloe Domain controllers'")
        assert "enloe" not in out.lower()
        # the whole-name key can never fire (the FQDN pass wins on 'Enloe'),
        # so it must not sit in the mapping as an entry that never happens
        assert "Enloe Domain controllers" not in anon.named_obj_map

    def test_user_named_like_a_known_fqdn_is_owned_by_the_fqdn_pass(self, anon):
        anon.register_fqdn("ehs")
        assert anon.anon_user("ehs") == "ehs"
        assert "ehs" not in anon.user_map


class TestRedactBinaries:
    """Opt-in: binary payloads that embed mapping identifiers are replaced by
    REDACTED_PAYLOAD instead of shipping the identifiers. The compare treats a
    *warranted* redaction as anonymization, and an unwarranted one as a
    warning — verified against the original, never trusted."""

    def test_binary_with_identifiers_is_redacted_and_compare_is_clean(self, tmp_path, tsf):
        from tsf_anonymizer.compare import compare_archives
        from tsf_anonymizer.core import REDACTED_PAYLOAD
        out = tmp_path / "out.tgz"
        report, mapping = anonymize_tsf(tsf, out, redact_binaries=True)
        assert report.redacted >= 2  # rule-hit-count.bin and core.1.gz both embed Zone-Prod-DMZ
        assert read_member(out, "./var/log/pan/rule-hit-count.bin") == REDACTED_PAYLOAD
        assert gzip.decompress(read_member(out, "./var/log/pan/core.1.gz")) == REDACTED_PAYLOAD
        rep = compare_archives(tsf, out, mapping)
        assert rep.summary["errors"] == 0
        assert rep.summary["binary_redacted"] == report.redacted
        assert rep.summary["binary_files_with_identifiers"] == 0

    def test_redaction_off_by_default_keeps_binaries_byte_identical(self, tmp_path, tsf):
        out = tmp_path / "out.tgz"
        report, _ = anonymize_tsf(tsf, out)
        assert report.redacted == 0
        from conftest import BINARY_PAYLOAD
        assert read_member(out, "./var/log/pan/rule-hit-count.bin") == BINARY_PAYLOAD

    def test_unwarranted_redaction_is_a_warning(self, tmp_path):
        from tsf_anonymizer.compare import MappingIndex, compare_one
        from tsf_anonymizer.core import REDACTED_PAYLOAD
        (tmp_path / "o").mkdir(); (tmp_path / "a").mkdir()
        (tmp_path / "o/x.bin").write_bytes(b"\x00\x01 nothing identifying \xff")
        (tmp_path / "a/x.bin").write_bytes(REDACTED_PAYLOAD)
        rep = compare_one("x.bin", tmp_path / "o/x.bin", tmp_path / "a/x.bin",
                          MappingIndex({"usernames": {"jdoe": "user001"}}))
        assert rep.status == "warning"
        assert rep.redacted

    def test_parallel_redaction_matches_sequential(self, tmp_path, tsf):
        out1, out2 = tmp_path / "s.tgz", tmp_path / "p.tgz"
        _, m1 = anonymize_tsf(tsf, out1, redact_binaries=True, workers=1)
        _, m2 = anonymize_tsf(tsf, out2, redact_binaries=True, workers=2)
        assert m1 == m2
        assert read_member(out1, "./var/log/pan/rule-hit-count.bin") \
            == read_member(out2, "./var/log/pan/rule-hit-count.bin")
        assert read_member(out1, "./var/log/pan/core.1.gz") \
            == read_member(out2, "./var/log/pan/core.1.gz")


class TestBatchErrorFixes:
    """Regressions from the first full 8-TSF batch (2026-08-31): the two jobs
    that ended in errors, one root cause per test."""

    def test_www_never_rewrites_vendor_xml_namespaces(self, anon):
        assert anon.register_named_object("www", "svc") == "www"
        anon.build_patterns()
        line = '<x xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
        assert anon.anonymize_text(line) == line

    def test_object_after_double_slash_is_a_url_authority_not_an_object(self, anon):
        anon.register_named_object("GW-Paris", "gw")
        anon.build_patterns()
        out = anon.anonymize_text("see http://GW-Paris.acme.example/ and gateway GW-Paris up")
        assert "http://GW-Paris.acme.example/" in out       # URL host: not an object
        assert "gateway GW-Paris up" not in out              # standalone: replaced

    def test_bruteforce_login_vocabulary_is_not_a_username(self, anon):
        for word in ("error", "request", "block", "usr"):
            line = f"failed authentication for user '{word}'.  Reason: Invalid username/password."
            assert anon.anonymize_text(line) == line
        assert not anon.user_map

    def test_username_glued_to_a_timestamp_is_still_replaced(self, anon):
        anon.anon_user("jdupont")
        anon.build_patterns()
        out = anon.anonymize_text("by jdupont2026-01-31 09:00:00")
        assert "jdupont" not in out

    def test_address_value_with_cidr_is_owned_by_the_ip_pass(self, tmp_path, anon):
        xml = ('<config><devices><server><entry name="s1">'
               '<address>10.18.2.254/24</address></entry></server></devices></config>')
        p = tmp_path / "config.xml"
        p.write_text(xml)
        prescan_config_xml(p, anon)
        assert "10.18.2.254/24" not in anon.fqdn_map
        anon.build_patterns()
        out = anon.anonymize_text("<address>10.18.2.254/24</address>")
        assert out.endswith("/24</address>")                 # the netmask survives
        assert "10.18.2.254" not in out                      # the address does not


def test_email_case_variants_share_one_pseudonym(anon):
    out = anon.anonymize_text("from JDupont@acme-corp.fr and jdupont@Acme-Corp.fr")
    fakes = {w for w in out.split() if "@" in w}
    assert len(fakes) == 1
    assert len(anon.email_map) == 1


class TestDeviceNameEverywhere:
    """The device's own name is in the techsupport txt *file name* and in
    `show system info` — and a name without a digit or hyphen went out in
    clear on three of four real TSFs, in a member name and in the text."""

    @pytest.fixture
    def output(self, tmp_path, tsf):
        out = tmp_path / "out.tgz"
        report, mapping = anonymize_tsf(tsf, out)
        return out, report, mapping

    def test_member_named_after_the_device_is_renamed(self, output):
        out, report, _ = output
        with tarfile.open(out) as tar:
            names = [m.name for m in tar.getmembers()]
        assert not any("fw-paris-01" in n for n in names)
        renamed = [n for n in names if n.startswith("./tmp/cli/techsupport_host")]
        assert len(renamed) == 1 and renamed[0].endswith("_20260407_1000.txt")
        assert report.members_renamed == 1

    def test_devicename_from_show_system_info_is_redacted(self, output):
        out, _, _ = output
        from conftest import DEVICE_NAME
        with tarfile.open(out) as tar:
            member = next(m for m in tar.getmembers() if "techsupport_host" in m.name)
            payload = tar.extractfile(member).read()
        assert DEVICE_NAME.encode() not in payload
        assert b"fw-paris-01" not in payload
        assert b"001901000123" not in payload
        assert b"model: PA-440" in payload                       # the model is not an identity
        assert b"techsupport_host" in payload                    # underscore-glued name in text, too

    def test_compare_pairs_the_renamed_member(self, tmp_path, tsf, output):
        from tsf_anonymizer.compare import compare_archives
        out, report, mapping = output
        rep = compare_archives(tsf, out, mapping)
        assert rep.ok and not rep.archive["mismatches"]
        assert rep.summary["members_renamed"] == 1
        assert rep.summary["errors"] == 0


def test_machine_account_marker_is_not_part_of_the_username(tmp_path, anon):
    xml = '<config><devices><users><entry name="acme\\pc01std$"/></users></devices></config>'
    p = tmp_path / "userinfo.xml"
    p.write_text(xml)
    prescan_config_xml(p, anon)
    assert "pc01std" in anon.user_map and "pc01std$" not in anon.user_map
    anon.build_patterns()
    out = anon.anonymize_text('<entry name="acme\\pc01std$"/>')
    assert "pc01std" not in out and out.endswith('$"/>')


def test_edl_cache_file_name_glued_to_its_vsys_is_rewritten(anon):
    """opt/pancfg/mgmt/devices/*/vsys1_<EDL name>.ebl: PAN-OS glues the object
    name to the vsys with an underscore — the only underscore that separates."""
    anon.register_named_object("ThreatFeed-Partner", "obj")
    anon.build_patterns()
    out = anon.anonymize_text("cache vsys1_ThreatFeed-Partner.ebl and my_ThreatFeed-Partner_x")
    assert "vsys1_OBJ-0001.ebl" in out
    assert "my_ThreatFeed-Partner_x" in out   # inside another identifier: untouched


class TestOneTrieForObjectsAndUsers:
    def test_service_named_like_a_first_name_does_not_eat_a_username(self, anon):
        """Service 'amanda' (the backup software) + user 'amanda.hudspeth':
        two tries in sequence produced SVC-0001.hudspeth — the surname leaked."""
        anon.register_named_object("amanda", "svc")
        anon.anon_user("amanda.hudspeth")
        anon.build_patterns()
        out = anon.anonymize_text("user amanda.hudspeth via service amanda")
        assert "hudspeth" not in out
        assert "user001" in out and "SVC-0001" in out

    def test_counts_still_split_users_from_objects(self, tmp_path, anon):
        anon.register_named_object("Zone-A", "zone")
        anon.anon_user("jdupont")
        anon.build_patterns()
        anon.anonymize_text("jdupont in Zone-A and Zone-A")
        assert anon.last_counts == {"usernames": 1, "named_objects": 2}


class TestSysdKeysAreNotEmails:
    @pytest.mark.parametrize("line", [
        "cfg.net.s6.eth2@252.acl-debug: { 'disable': False, }",
        '<obj name="cfg.net.s6.eth2@252.acl-debug" type="dict">',
        "NET: acl: eth3@252: cfg.net.s6.eth3@252.acl-debug - x",
    ])
    def test_interface_at_vlan_keys_are_left_alone(self, anon, line):
        assert anon.anonymize_text(line) == line
        assert not anon.email_map and not anon.fqdn_map

    def test_real_addresses_still_match(self, anon):
        out = anon.anonymize_text("mail ops@acme-corp.fr, alert to j.doe@mail.example.org.")
        assert "acme-corp.fr" not in out and "j.doe" not in out


class TestBinaryHeuristic:
    """Ratios measured on eight real TSFs (see is_binary_bytes)."""

    def test_console_log_with_a_stray_nul_is_text(self):
        from tsf_anonymizer.core import is_binary_bytes
        chunk = (b"Tue Aug 26 20:48:43 2025: Welcome to the PanOS Bootloader.\n" * 60)[:4000] + b"\x00" + b"ok\n" * 30
        assert not is_binary_bytes(chunk)

    def test_length_prefixed_record_format_is_binary(self):
        from tsf_anonymizer.core import is_binary_bytes
        rec = b"\x00\x00\x05\xfe\xfe\x04\xa6\x7f\x03\x01\x01\nGpTaskStat\x01\xff\x80\x00\x01>\x01\x06TaskId\x01\x06\x00\x01\x08VsysName\x01\x0c\x00"
        assert is_binary_bytes(rec * 100)

    def test_compressed_stream_is_binary(self):
        import random

        from tsf_anonymizer.core import is_binary_bytes
        random.seed(3)
        chunk = bytes(random.randrange(256) for _ in range(4096))
        assert is_binary_bytes(chunk)

    def test_edl_cache_is_text(self, tmp_path):
        p = tmp_path / "vsys1_Feed.ebl"
        p.write_bytes(b"10.0.0.1\n10.0.0.2\n" * 50)
        assert not is_binary_file(p)


def test_brute_force_word_port_is_not_a_username(anon):
    line = "failed authentication for user 'port'.  Reason: Invalid username/password."
    assert anon.anonymize_text(line) == line


def test_hostname_inside_a_hyphenated_compound_is_still_the_device(anon):
    """adm-<hostname> (the admin UI's DNS name) and <hostname>-PBP-ALERTE
    survived a real run: the hyphen rule is for objects, not hostnames."""
    anon.register_fqdn("fw-dc1")
    anon.register_named_object("web", "addr")
    anon.build_patterns()
    out = anon.anonymize_text('host: "adm-fw-dc1", referrer: "https://adm-fw-dc1/" profile fw-dc1-PBP-ALERTE web-server-1')
    assert "fw-dc1" not in out
    assert "adm-host001" in out and "host001-PBP-ALERTE" in out
    assert "web-server-1" in out            # objects keep the hyphenated-compound rule


def test_member_renaming_never_touches_directories(tmp_path, tsf):
    """A user named `cli` renamed tmp/cli/ to tmp/user83115/ on a real run."""
    from tsf_anonymizer.core import mapped_member_name
    assert mapped_member_name(lambda s: s.replace("cli", "user001"), "./tmp/cli/cli_netstat.txt") \
        == "./tmp/cli/user001_netstat.txt"
    assert mapped_member_name(lambda s: "X", ".") == "."
    assert mapped_member_name(lambda s: "X", "./tmp/cli") == "./tmp/X"   # only the last component
