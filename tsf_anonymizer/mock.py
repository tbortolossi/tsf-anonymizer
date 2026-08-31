"""A synthetic PAN-OS tech support file, for demos, docs and screenshots.

Real TSFs are customer material and never enter this repository, so anything
that has to *show* the tool -- the documentation screenshots, a first run
after ``pip install``, a bug report that needs a reproducer -- works on the
archive this module writes. It has the layout the anonymizer and the
``read-tsf`` skill expect (``opt/pancfg``, ``var/log/pan``, ``tmp/cli``),
the identifier classes the anonymizer handles (private and public IPs,
FQDNs, e-mails, named objects, usernames, serials, a device name known only
to ``show system info``), rotated ``.gz`` logs, a file shipped in mode 0000,
and a couple of binary payloads that embed identifiers -- the case the
compare report flags.

Every value is fictional: the company is ``acme-corp``, public addresses come
from the RFC 2544 benchmarking range and the serial is a made-up number. The
generator is deterministic for a given seed, so two runs produce the same
archive and the same mapping.
"""

from __future__ import annotations

import gzip
import io
import random
import tarfile
import time
from pathlib import Path

DEVICE = "fw-paris-01"
DOMAIN = "acme-corp.local"
MAIL_DOMAIN = "acme-corp.fr"
SERIAL = "001901000123"
MGMT_IP = "172.16.4.1"
PEER_PUBLIC = "198.18.7.7"  # RFC 2544 benchmarking range: reserved, never routed

USERS = ["jean.dupont", "m.garcia", "s.nakamura", "ops-admin", "p.oconnor"]
# Three are declared in the config; `nas-paris` is not -- it only ever appears in
# logs, which is the documented limitation a raw grep of the output still catches.
INTERNAL_HOSTS = ["dc01", "dc02", "web-prod-01", "nas-paris"]
ZONES = ["Zone-Prod-DMZ", "Zone-Users-Paris", "Zone-Servers", "Zone-VPN-Partners"]
ADDRESSES = {
    "SRV-Compta-Paris": "10.20.30.40/32",
    "NET-Users-Paris": "10.20.40.0/24",
    "NET-Servers": "10.20.50.0/24",
    "Partner-Lyon-Public": "198.18.9.21/32",
}
RULES = ["Allow-Compta-to-DMZ", "Allow-Users-Web", "Block-Partners-SMB", "Allow-VPN-Partners"]
GATEWAYS = ["GW-Paris-Primary", "GW-Lyon-Backup"]

_CONFIG = """<?xml version="1.0"?>
<config version="11.1.0" urldb="paloaltonetworks">
  <mgt-config>
    <users>
      <entry name="admin"><permissions><role-based><superuser>yes</superuser></role-based></permissions></entry>
      <entry name="{admin_user}"><permissions><role-based><superuser>yes</superuser></role-based></permissions></entry>
    </users>
  </mgt-config>
  <devices>
    <entry name="localhost.localdomain">
      <deviceconfig><system>
        <hostname>{device}</hostname>
        <domain>{domain}</domain>
        <serial>{serial}</serial>
        <ip-address>{mgmt_ip}</ip-address>
        <netmask>255.255.255.0</netmask>
        <default-gateway>172.16.4.254</default-gateway>
        <dns-setting><servers><primary>10.20.50.10</primary><secondary>10.20.50.11</secondary></servers></dns-setting>
        <ntp-servers><primary-ntp-server><ntp-server-address>0.pool.ntp.org</ntp-server-address></primary-ntp-server></ntp-servers>
        <login-banner>Authorized access only.</login-banner>
      </system></deviceconfig>
      <vsys><entry name="vsys1">
        <zone>
{zones}
        </zone>
        <address>
{addresses}
          <entry name="web server prod"><fqdn>web-prod-01.{domain}</fqdn></entry>
        </address>
        <rulebase><security><rules>
{rules}
        </rules></security></rulebase>
      </entry></vsys>
      <network>
        <interface><ethernet>
          <entry name="ethernet1/1"><layer3><ip><entry name="10.20.30.1/24"/></ip></layer3></entry>
          <entry name="ethernet1/2"><layer3><ip><entry name="10.20.40.1/24"/></ip></layer3></entry>
        </ethernet></interface>
        <ike><gateway>
{gateways}
        </gateway></ike>
      </network>
    </entry>
  </devices>
  <shared>
    <server-profile><ldap><entry name="LDAP-Prod">
      <server>
        <entry name="dc01"><address>dc01.{domain}</address><port>636</port></entry>
        <entry name="dc02"><address>dc02.{domain}</address><port>636</port></entry>
      </server>
      <base>DC=acme-corp,DC=local</base>
      <bind-dn>CN=svc-pan,OU=Services,DC=acme-corp,DC=local</bind-dn>
    </entry></ldap></server-profile>
    <log-settings><email><entry name="mail-ops"><to>ops@{mail_domain}</to><from>{device}@{mail_domain}</from></entry></email></log-settings>
    <certificate><entry name="cert-gp"><subject>C = FR, O = AcmeCorp, CN = vpn.{mail_domain}</subject></entry></certificate>
  </shared>
</config>
"""

_TECHSUPPORT = """\
> show clock
Tue Apr  7 10:00:00 CEST 2026
> show system info
hostname: {device}
devicename: {devicename}
domain: {domain}
ip-address: {mgmt_ip}
netmask: 255.255.255.0
default-gateway: 172.16.4.254
mac-address: 00:1b:17:00:00:01
serial: {serial}
model: PA-440
sw-version: 11.1.4-h7
app-version: 8950-9210
uptime: 42 days, 3:17:09
> show system files
/opt/panlogs/tmp/techsupport/{ts_name}
> show interface all
name                    id    speed/duplex/state        mac address
ethernet1/1             16    1000/full/up              00:1b:17:00:00:10
ethernet1/2             17    1000/full/up              00:1b:17:00:00:11
> show routing route
destination        nexthop            metric flags  interface
0.0.0.0/0          172.16.4.254       10     A S    ethernet1/1
10.20.30.0/24      10.20.30.1         0      A C    ethernet1/1
10.20.40.0/24      10.20.40.1         0      A C    ethernet1/2
> show high-availability state
Group 1:
  Mode: Active-Passive
  Local Information:
    State: active
    Priority: 100
  Peer Information:
    Connection status: up
    State: passive
    Serial: 001901000124
"""


def _indent(lines: list[str], n: int = 10) -> str:
    pad = " " * n
    return "\n".join(pad + line for line in lines)


def render_config() -> str:
    zones = [f'<entry name="{z}"><network><layer3><member>ethernet1/{i % 2 + 1}</member></layer3></network></entry>'
             for i, z in enumerate(ZONES)]
    addresses = [f'<entry name="{n}"><ip-netmask>{v}</ip-netmask></entry>' for n, v in ADDRESSES.items()]
    rules = []
    for i, r in enumerate(RULES):
        src = list(ADDRESSES)[i % len(ADDRESSES)]
        rules.append(
            f'<entry name="{r}"><from><member>{ZONES[i % len(ZONES)]}</member></from>'
            f'<to><member>{ZONES[(i + 1) % len(ZONES)]}</member></to>'
            f'<source><member>{src}</member></source><destination><member>any</member></destination>'
            f'<application><member>web-browsing</member></application><action>allow</action>'
            f'<description>Ticket CHG-{1000 + i}</description></entry>')
    gateways = [f'<entry name="{g}"><peer-address><ip>{PEER_PUBLIC[:-1]}{i + 7}</ip></peer-address>'
                f'<local-address><ip>{MGMT_IP}</ip></local-address></entry>'
                for i, g in enumerate(GATEWAYS)]
    return _CONFIG.format(device=DEVICE, domain=DOMAIN, serial=SERIAL, mgmt_ip=MGMT_IP,
                          mail_domain=MAIL_DOMAIN, admin_user=USERS[3],
                          zones=_indent(zones), addresses=_indent(addresses),
                          rules=_indent(rules), gateways=_indent(gateways))


def render_logs(rng: random.Random, lines: int) -> dict[str, str]:
    """A few daemon logs with the phrasings the anonymizer knows, in the
    volume the caller asks for (``lines`` per file)."""
    t0 = 1775548800  # 2026-04-07 10:00:00 UTC
    def stamp(i: int) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(t0 + i * 7))
    def host_ip() -> str:
        return f"10.20.{rng.choice([30, 40, 50])}.{rng.randint(2, 250)}"

    system, authd, ikemgr, useridd, nginx = [], [], [], [], []
    for i in range(lines):
        u = rng.choice(USERS)
        h = rng.choice(INTERNAL_HOSTS)
        ip = host_ip()
        system.append(rng.choice([
            f"{stamp(i)} [mgd] commit by user '{u}' from {ip} succeeded (job {4000 + i})",
            f"{stamp(i)} [routed] 10.20.{rng.randint(30, 50)}.0/24 via ethernet1/1 metric 10",
            f"{stamp(i)} [ldap] bind to {h}.{DOMAIN} rc=0 latency={rng.randint(1, 40)}ms",
            f"{stamp(i)} [rule] {rng.choice(RULES)} matched src {rng.choice(list(ADDRESSES))} "
            f"zone {rng.choice(ZONES)}",
            f"{stamp(i)} [mail] alert sent to {u}@{MAIL_DOMAIN}",
            f"{stamp(i)} [dhcpd] lease 10.20.40.{rng.randint(2, 250)} for {h} renewed",
        ]))
        authd.append(rng.choice([
            f"{stamp(i)} authd: authenticated for user '{u}' from {ip} via LDAP-Prod",
            f"{stamp(i)} authd: failed authentication for user '{u}' from {ip} (reason: bad password)",
            f"{stamp(i)} authd: failed authentication for user 'error' from {PEER_PUBLIC} (reason: invalid)",
        ]))
        ikemgr.append(rng.choice([
            f"{stamp(i)} ikemgr: IKEv2 SA established peer {PEER_PUBLIC} gateway {rng.choice(GATEWAYS)} "
            f"spi={rng.getrandbits(32):08x}",
            f"{stamp(i)} ikemgr: DPD timeout peer {PEER_PUBLIC} gateway {GATEWAYS[1]} retries=3",
            f"{stamp(i)} ikemgr: keepalive to {PEER_PUBLIC} epoch {t0 * 1000 + i}",
        ]))
        useridd.append(f"{stamp(i)} useridd: ip-user mapping {ip} -> acme-corp\\{u} timeout=2700 "
                       f"source=agent {h}.{DOMAIN}")
        nginx.append(f'{ip} - - [07/Apr/2026:10:{i % 60:02d}:00 +0200] "GET /php/login.php HTTP/1.1" '
                     f'200 {rng.randint(300, 9000)} "-" "Mozilla/5.0" host=adm-{DEVICE}.{DOMAIN}')
    return {
        "var/log/pan/system.log": "\n".join(system) + "\n",
        "var/log/pan/authd.log": "\n".join(authd) + "\n",
        "var/log/pan/ikemgr.log": "\n".join(ikemgr) + "\n",
        "var/log/pan/useridd.log": "\n".join(useridd) + "\n",
        "var/log/nginx/access.log": "\n".join(nginx) + "\n",
    }


def techsupport_name(device: str = DEVICE) -> str:
    return f"techsupport_{device}_20260407_1000.txt"


def build_mock_tsf(output: Path, *, lines: int = 400, seed: int = 7) -> Path:
    """Write the synthetic archive to ``output`` and return its path.

    ``lines`` is the number of lines per log file: 400 (the default) makes an
    archive that runs in a few seconds; 20 000 makes one large enough for the
    progress bars to be worth watching.
    """
    rng = random.Random(seed)
    members: list[tuple[str, bytes, int]] = []  # (path, payload, mode)

    def add(path: str, payload: bytes | str, mode: int = 0o644) -> None:
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        members.append((path, payload, mode))

    add("opt/pancfg/mgmt/saved-configs/running-config.xml", render_config())
    add("tmp/cli/" + techsupport_name(), _TECHSUPPORT.format(
        device=DEVICE, devicename="CoreFirewallParis", domain=DOMAIN, mgmt_ip=MGMT_IP,
        serial=SERIAL, ts_name=techsupport_name()))
    logs = render_logs(rng, lines)
    for path, text in logs.items():
        add(path, text)
        # Two rotations of each log, compressed, with older content.
        older = render_logs(random.Random(seed + 1), max(10, lines // 4))[path]
        for n in (1, 2):
            add(f"{path}.{n}.gz", gzip.compress(older.encode("utf-8"), compresslevel=6))
    # A file real TSFs ship in mode 0000 (the archive must keep that mode).
    add("opt/pancfg/mgmt/global/.hcr_metadata.json", f'{{"peer": "{MGMT_IP}", "serial": "{SERIAL}"}}\n', 0o000)
    add("var/log/pan/rule-hit-count-db.txt",
        "".join(f"vsys1 {r} hits={rng.randint(0, 99999)}\n" for r in RULES))
    # Binary payloads that embed identifiers: not rewritten, flagged by the compare.
    add("var/log/pan/rule-hit-count.bin",
        b"\x00\x01\x00\x10" + b"\x00".join(r.encode() for r in RULES) + b"\xff\xfe\x00\x00" * 64)
    add("var/log/wtmp", (b"\x07\x00\x00\x00" + b"\x00" * 60 + MGMT_IP.encode() + b"\x00" * 300) * 12)
    add("var/log/pan/untouched.txt", "nothing identifying here\n")

    mtime = 1775548800
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    # gzip's header carries a file name and a timestamp: pin both so the bytes
    # do not depend on the output path or the clock.
    with open(output, "wb") as raw, \
            gzip.GzipFile(filename="", mode="wb", compresslevel=6, fileobj=raw, mtime=mtime) as gz, \
            tarfile.open(fileobj=gz, mode="w") as tar:
        seen_dirs: set[str] = set()
        for path, payload, mode in members:
            parts = path.split("/")[:-1]
            for i in range(1, len(parts) + 1):
                d = "/".join(parts[:i])
                if d in seen_dirs:
                    continue
                seen_dirs.add(d)
                info = tarfile.TarInfo("./" + d)
                info.type, info.mode, info.mtime = tarfile.DIRTYPE, 0o755, mtime
                info.uid = info.gid = 1234
                info.uname = info.gname = "pan"
                tar.addfile(info)
            info = tarfile.TarInfo("./" + path)
            info.size, info.mode, info.mtime = len(payload), mode, mtime
            info.uid = info.gid = 1234
            info.uname = info.gname = "pan"
            tar.addfile(info, io.BytesIO(payload))
    return output


def default_mock_name(device: str = DEVICE) -> str:
    """What a human would name the archive PAN-OS gave them: the device, then
    PAN-OS's own ``<date>_<time>_techsupport`` part -- the shape the web UI's
    device guess is built for."""
    return f"{device}_20260407_1000_techsupport.tgz"
