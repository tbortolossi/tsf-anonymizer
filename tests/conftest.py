"""Shared fixtures: a small but realistic TSF archive."""

from __future__ import annotations

import gzip
import tarfile
import time
from pathlib import Path

import pytest

CONFIG_XML = """<?xml version="1.0"?>
<config version="10.2.0">
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig><system>
        <hostname>fw-paris-01</hostname>
        <domain>acme-corp.local</domain>
        <serial>001901000123</serial>
        <ip-address>172.16.4.1</ip-address>
        <ntp-servers><primary-ntp-server><ntp-server-address>0.pool.ntp.org</ntp-server-address></primary-ntp-server></ntp-servers>
      </system></deviceconfig>
      <vsys><entry name="vsys1">
        <zone>
          <entry name="Zone-Prod-DMZ"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
          <entry name="trust"/>
        </zone>
        <address>
          <entry name="SRV-Compta-Paris"><ip-netmask>10.20.30.40/32</ip-netmask></entry>
          <entry name="web server prod"><fqdn>web.acme-corp.local</fqdn></entry>
        </address>
        <rulebase><security><rules>
          <entry name="Allow-Compta-to-DMZ"><from><member>trust</member></from><to><member>Zone-Prod-DMZ</member></to>
            <source><member>SRV-Compta-Paris</member></source><action>allow</action></entry>
        </rules></security></rulebase>
      </entry></vsys>
      <network><ike><gateway>
        <entry name="GW-Paris-Primary"><peer-address><ip>203.0.113.7</ip></peer-address></entry>
      </gateway></ike></network>
    </entry>
  </devices>
  <shared>
    <server-profile><ldap><entry name="LDAP-Prod">
      <server><entry name="dc01"><address>dc01.acme-corp.local</address></entry></server>
      <base>DC=acme-corp,DC=local</base>
      <bind-dn>CN=svc-pan,OU=Services,DC=acme-corp,DC=local</bind-dn>
    </entry></ldap></server-profile>
    <log-settings><email><entry name="mail-ops"><to>ops@acme-corp.fr</to></entry></email></log-settings>
    <certificate><entry name="cert-gp"><subject>C = FR, O = AcmeCorp, CN = vpn.acme-corp.fr</subject></entry></certificate>
  </shared>
</config>
"""

LOG_SAMPLE = """\
2026-04-07 10:00:01 [authd] authenticated for user 'jean.dupont' from 172.16.4.9
2026-04-07 10:00:02 [ikemgr] peer IP 203.0.113.7 gateway GW-Paris-Primary up (epoch 1743840000123)
2026-04-07 10:00:03 [mgd] device serial 001901000123 committed by user 'admin' pid 4711
2026-04-07 10:00:04 [ldap] bind to dc01.acme-corp.local failed rc=49
2026-04-07 10:00:05 [mail] alert sent to jean.dupont@acme-corp.fr
2026-04-07 10:00:06 [routed] 192.168.10.0/24 via ethernet1/1 metric 10
2026-04-07 10:00:07 [syslog] forwarding to undeclared-host.acme-corp.local
2026-04-07 10:00:08 [rule] Allow-Compta-to-DMZ matched src SRV-Compta-Paris zone Zone-Prod-DMZ
fw-paris-01(active)> show clock\r
Apr  7 10:00:09 fw-paris-01 kernel: caf\xe9 latin-1 byte survives
"""

IDENTIFIERS = [
    "jean.dupont", "172.16.4.9", "203.0.113.7", "001901000123", "dc01.acme-corp.local",
    "acme-corp.fr", "GW-Paris-Primary", "Zone-Prod-DMZ", "SRV-Compta-Paris",
    "Allow-Compta-to-DMZ", "fw-paris-01", "10.20.30.40",
]

# The command dump PAN-OS names after the *device*, not the model — and the
# devicename below has no digit or hyphen, which the log-phrase heuristic
# would reject: only `show system info` can vouch for it.
TECHSUPPORT_NAME = "techsupport_fw-paris-01_20260407_1000.txt"
TECHSUPPORT_TXT = """\
> show clock
Tue Apr  7 10:00:00 CEST 2026
> show system info
hostname: fw-paris-01
devicename: CoreFirewallParis
ip-address: 172.16.4.1
serial: 001901000123
model: PA-440
sw-version: 11.1.4
> show system files
/opt/panlogs/tmp/techsupport/techsupport_fw-paris-01_20260407_1000.txt
"""
DEVICE_NAME = "CoreFirewallParis"
PRESERVED = ["ethernet1/1", "'admin'", "1743840000123", "pid 4711", "metric 10", "rc=49",
             "2026-04-07 10:00:01", "Apr  7 10:00:09", "/24"]

BINARY_PAYLOAD = b"\x00\x01binary Zone-Prod-DMZ 172.16.4.9 \xff\xfe"


def build_tsf(tmp_path: Path, name: str = "in.tgz") -> Path:
    staging = tmp_path / "staging"
    (staging / "opt/pancfg/mgmt/saved-configs").mkdir(parents=True)
    (staging / "var/log/pan").mkdir(parents=True)
    (staging / "opt/pancfg/mgmt/saved-configs/running-config.xml").write_text(CONFIG_XML)
    (staging / "var/log/pan/system.log").write_bytes(_latin(LOG_SAMPLE))
    (staging / "var/log/pan/rule-hit-count.bin").write_bytes(BINARY_PAYLOAD)
    (staging / "var/log/pan/untouched.txt").write_text("nothing identifying here\n")
    (staging / "tmp/cli").mkdir(parents=True)
    (staging / "tmp/cli" / TECHSUPPORT_NAME).write_text(TECHSUPPORT_TXT)
    # A real TSF ships files in mode 0000 (opt/pancfg/mgmt/global/.hcr_metadata.json).
    (staging / "opt/pancfg/mgmt/global").mkdir(parents=True)
    (staging / "opt/pancfg/mgmt/global/.hcr_metadata.json").write_text('{"peer": "172.16.4.9"}\n')
    with gzip.open(staging / "var/log/pan/system.log.1.gz", "wb") as f:
        f.write(_latin(LOG_SAMPLE))
    with gzip.open(staging / "var/log/pan/core.1.gz", "wb") as f:
        f.write(BINARY_PAYLOAD)

    archive = tmp_path / name
    mtime = int(time.time()) - 86400
    with tarfile.open(archive, "w:gz") as tar:
        for p in sorted(staging.rglob("*")):
            info = tar.gettarinfo(p, arcname="./" + str(p.relative_to(staging)))
            info.mtime, info.uid, info.gid, info.uname, info.gname = mtime, 1234, 1234, "pan", "pan"
            if p.name == ".hcr_metadata.json":
                info.mode = 0o000
            if p.is_file():
                with open(p, "rb") as f:
                    tar.addfile(info, f)
            else:
                tar.addfile(info)
    return archive


def _latin(s: str) -> bytes:
    """LOG_SAMPLE holds an `é`: write it as a single Latin-1 byte (0xE9), the
    way a PAN-OS log that is not UTF-8 would."""
    return s.encode("utf-8").replace("\xe9".encode("utf-8"), b"\xe9")


@pytest.fixture
def tsf(tmp_path) -> Path:
    return build_tsf(tmp_path)


def read_member(archive: Path, member: str) -> bytes:
    with tarfile.open(archive, "r:gz") as tar:
        return tar.extractfile(member).read()
