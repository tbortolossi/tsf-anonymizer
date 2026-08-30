"""Anonymizer tests — assert on the *output*: nothing identifying survives,
everything debugging depends on does."""

from __future__ import annotations

import gzip
import json
import tarfile

import pytest

from tsf_anonymizer.core import (
    Anonymizer, anonymize_tsf, is_binary_file, mapping_sidecar_path, process_file,
    prescan_config_xml, _is_panos_interface,
)
from conftest import CONFIG_XML, IDENTIFIERS, PRESERVED, BINARY_PAYLOAD, read_member


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
        out, _, _ = output
        with tarfile.open(tsf) as a, tarfile.open(out) as b:
            ma, mb = a.getmembers(), b.getmembers()
        assert [m.name for m in ma] == [m.name for m in mb]
        for x, y in zip(ma, mb):
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
        assert report.files_total == 7
        assert report.modified == 4          # log, gz log, config, mode-0000 json
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
        assert set(anon.fqdn_map) == {"vpn.acme.fr"}

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
