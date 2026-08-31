# Reading a PAN-OS Tech Support File

A practical guide to what a TSF contains, where to look, and in which order —
written for someone who has one on disk and a problem to explain.
The layout below is what a PAN-OS 12.x PA-440 produces; older releases and
Panorama differ in details, not in shape.

## 1. What a TSF is

A **tech support file** is a gzipped tar (`<date>_<time>_techsupport.tgz`,
typically 100–400 MB) that PAN-OS assembles on request. It is a snapshot of
three things:

1. **The device's configuration** — running, candidate, saved copies, and what
   Panorama pushed.
2. **The daemon logs** from `/var/log/pan/`, with their rotations — usually 5 to
   30 days of history depending on how chatty the box is.
3. **The output of several hundred `show` / `debug` commands**, run at
   generation time, captured into one big text file.

Generate it from **Device › Support › Generate Tech Support File** (GUI), or
from the CLI with `request tech-support dump` followed by
`scp export tech-support to user@host:/path`. Generating takes 5–15 minutes
and briefly loads the management plane; on a struggling box, do it anyway —
the state you want is the state it is in now.

Two dates matter and they are not the same:

- the **generation time**, in the filename and at the top of
  `tmp/cli/techsupport_*.txt` (`> show clock`);
- the **device timezone**, printed by the same `show clock`
  (`Sun Apr  5 09:36:57 CEST 2026`). Every log line inside the TSF is in that
  timezone, with no offset written. If you correlate with an external
  system (SIEM, Panorama, a customer's e-mail), convert first.

## 2. Layout

```
./tmp/cli/techsupport_<devicename>_<YYYYMMDD>_<HHMM>.txt   ← START HERE: all show/debug output
                                           (named after the device, never the model)
./tmp/cli/logs/                            ← a few big command outputs kept apart
    show_log_system.txt, show_log_config.txt, show_log_globalprotect.txt,
    show_log_alarm.txt, show_log_journal.txt, show_log_systemd.txt,
    cli_netstat.txt, fs_manifest.txt, sdb.txt, pdt.txt, pmap_mgmtsrvr.txt,
    online_diags_run_log.txt, cpld_dumps.txt, scheduled_report_listing.txt
./opt/pancfg/mgmt/saved-configs/
    running-config.xml                     ← the config in force
    techsupport-saved-currcfg.xml          ← candidate at generation time
    .merged-running-config.xml             ← local + Panorama-pushed, merged
    .ha-remote-rc.xml                      ← the HA peer's running config
./opt/pancfg/mgmt/devices/localhost.localdomain/
    platform.xml                           ← capacity limits PAN-OS enforces
    candidatecfg.<n>.xml, last-candidatecfg.xml
    rule-hit-count-db.txt, rule-hit-count.bin
    global-external-list.xml               ← EDL contents
    vsys<n>_<EDL name>.ebl                 ← per-EDL binary cache (IP lists; spaces in the name become #)
./opt/pancfg/mgmt/tmp/panorama_pushed/     ← what Panorama sent (before/after import)
./opt/pancfg/mgmt/audit/cfg-audit.xml,v    ← RCS history of every commit
./opt/pancfg/mgmt/global/                  ← content/AV version info, report configs
./opt/pancfg/mgmt/healthchecks/            ← periodic health snapshots (.cli, .xml)
./opt/pancfg/mgmt/updates/{cur,old}content/global/global.xml  ← the App-ID/Threat DB (37 MB, ignore)
./var/log/pan/                             ← DAEMON LOGS (see §4)
./opt/var.dp<n>/log/pan/                   ← per-dataplane logs (PA-5200); opt/var.cp/ = control plane
./opt/var/s<slot>/{dp<n>,cp,lfp<n>}/log/pan/  ← PA-7000: per slot — dataplanes, card CP, log processing cards
./var/log/pan/crashinfo/                   ← *.info sidecars, one per crash (absent = no crash)
./var/log/{messages,audit/,nginx/,ntpstats/,sa/}  ← Linux side: kernel, auth, web, NTP, sar
./opt/panrepo/logs/                        ← boot history: bios.log, reboot.log, swm.log, history.log
./etc/frr/                                 ← routing daemon config (advanced routing engine)
./opt/plugins/var/log/pan/                 ← plugin logs (adem, dlp, …)
```

Rotation conventions in `var/log/pan/`: `<daemon>.log` is live, `<daemon>.log.old`
or `.1`, `.2`… are older, `.gz` are compressed rotations. **The failure window
is often only in a rotation** — a daemon that logs 10 MB an hour has rotated
the interesting hour away by the time the TSF is generated. Always list the
rotations before concluding "nothing in the log".

## 3. Where to start: the techsupport txt

`tmp/cli/techsupport_<model>_<date>.txt` is ~20 000 lines of `> command`
headers followed by output. Search for the `> ` prefix to navigate. The
sections worth reading on every case, in order:

| section | tells you |
|---|---|
| `> show system info` | model, serial, **PAN-OS version**, content/AV/threat versions, uptime, HA, mgmt IP |
| `> show clock` | device time and timezone (see §1) |
| `> show system resources` | CPU/memory on the management plane, top processes |
| `> show running resource-monitor` | dataplane CPU per core, and `Resource utilization (%)`: session, **packet buffer, packet descriptor (on-chip)** — read the *(maximum)* rows; descriptor saturation drops packets while CPU looks idle |
| `> show session info` | sessions in use vs. the limit, packet rate, throughput, timeouts |
| `> show counter global filter delta yes` | dataplane drop counters — **read the `drop` and `error` severities first** |
| `> show interface all` | link state, speed/duplex, errors per interface |
| `> show high-availability all` / `state-synchronization` / `path-monitoring` | HA state, why a failover happened |
| `> show jobs processed` | commit history with success/failure and duration |
| `> show system files` | crash files and core dumps present on the box |
| `> show system environmentals` | temperature, fans, power supplies |
| `> show system disk-space` / `> show system logdb-quota` | full disks, log partitions |
| `> show routing route` / `> show advanced-routing route` | the FIB, static/OSPF/BGP |
| `> show vpn ike-sa` / `> show vpn ipsec-sa` / `> show vpn flow` | tunnel state |
| `> show global-protect-gateway …` / `-portal …` | GP sessions, auth, statistics |
| `> show user ip-user-mapping-mp all` / `> show user user-id-agent statistics` | User-ID health |
| `> request license info` | licences and expiry (an expired licence explains many "it stopped working") |
| `> debug dataplane pool statistics` | dataplane pools — `Packet Buffers free/total` vs `Low free buffer limit`, `Depleted` segments; depleted pools drop packets silently |
| `> show zone-protection` | per-zone, per-mechanism `packet dropped:` counts — these drops write **no traffic log** |
| `> show system setting …` | tuning knobs that differ from defaults |

`> show counter global` appears twice: once raw and once as a delta over a
few seconds. The delta is the one that says what is happening *now*.

## 4. Daemon logs — which file for which problem

All under `var/log/pan/`. Daemon names are stable across releases, but **some
daemons have two log names and the newest is the live one**: on 11.1+ IKE
writes `ikemgr-ng.log` while `ikemgr.log` stays present and idle; same for
`keymgr`/`keymgr-ng` and `dnsproxyd`/`dnsproxy_go`/`dns-go-agent`. Check both.

| problem | read | then |
|---|---|---|
| commit failed / slow | `configd.log`, `commit_stats.log`, `show_log_config.txt` | `mgmt_httpd_error.log`, `cfg-audit.xml,v` for what changed |
| reboot / crash | `crashinfo/*.info`, `sysd.log`, `messages`, `opt/panrepo/logs/reboot.log` | `show system files`; `mp-monitor.log` for memory before the crash; `dataplane-console-output.log` (chassis: `controlplane-console-output.log` and `opt/var.cp/log/pan/dataplane<n>-console-output.log`) = the serial console (`Welcome to the PanOS Bootloader…`, timestamped) — the boot sequence and any panic text the kernel printed on the way down |
| HA failover | `ha_agent.log`, `show_log_system.txt` (filter `ha`) | `show high-availability all`; path/link monitoring config in `running-config.xml` |
| site-to-site VPN | `ikemgr-ng.log` (or `ikemgr.log`), `keymgr*.log` | `> debug ike stat …`, `show vpn ike-sa`, `show vpn ipsec-sa`; the peer's proposals in the config |
| GlobalProtect | `gpsvc.log`, `sslvpn-access.log`, `sslvpn_ngx_error.log`, `show_log_globalprotect.txt` (can be the biggest text file of the TSF — 64 MB seen; one row per portal/gateway event, columns: time, gateway/portal, status, event, region, `domain\user`) | `rasmgr.log`, `authd.log`, `sslmgr.log` (certs); `var/log/pan/sslvpn-access/sslvpn-task.log*.gz` are **binary** per-request records (`strings`/`grep -a`) |
| authentication (admin, GP, captive portal) | `authd.log` | `useridd.log` for group mapping, `sslmgr.log` for cert-based auth |
| User-ID | `useridd.log`, `distributord.log`, `redis_useridd.log` | `> show user …` sections |
| routing | `routed.log` (legacy) or `frr_export.log` + `var/log/pan/frr/` + `etc/frr/` (advanced routing) | `> show routing …` / `> show advanced-routing …`; `bfd.log` for BFD |
| interfaces / links | `pan_ifmgr.log`, `brdagent.log` (port/ASIC faults), `l2ctrld.log` | `> show interface all`, `show system environmentals` |
| performance / drops | `mp-monitor.log`, `dp-monitor.log`, `dp-sessperf_mon.log` | `> show running resource-monitor`, `show counter global filter delta yes`, `debug dataplane pool statistics` |
| content / AV updates | `paninstaller_content.log`, `curlog_out_*`, `contentd.log`, `md_*.log` | `> request content upgrade info`, `opt/pancfg/mgmt/global/*info.xml` |
| WildFire | `wildfire-monitor.log`, `wildfire-upload.log`, `wf_curl.log` | `> show wildfire status` |
| logging / log forwarding | `logrcvr.log`, `varrcvr.log`, `logging-services.log`, `logpurger.log` — on a PA-7000, under the log processing cards `opt/var/s<slot>/lfp<n>/log/pan/` (`logrcvr.log`, `syslog-ng.log`, `lfp-monitor.log`) | `> show logging-status`, `debug log-receiver statistics`; `redis_useridd.log`/`redis_mgmt.log` can be the biggest files of the TSF (200 MB seen) |
| reports | `reportd.log`, `report_gen.log`, `genreport.log`, `indexgen.log` | |
| SSL decryption / certificates | `sslmgr.log`, `device_certgen.log`, `uia_tsa_cert.log` | `> show device-certificate status`, `debug sslmgr statistics` |
| DHCP / DNS proxy | `pan_dhcpd.log`, `dhclient_debug.log`, `dnsproxy_go.log` | |
| Panorama connectivity | `devsrv.log`, `ms.log`, `configd.log` | `> show panorama-status` |
| web UI / API | `mgmt_httpd_access.log`, `mgmt_httpd_error.log`, `appweb3-panmodule.log`, `php.debug.log` | `dagger.log`: every operational command dispatched (`OPCMD: handler "session"` / `finish handler …`, timestamped) — what was run from CLI/API, and when |
| disk | `logdb_dirs_gen.log`, `panlogs-partition.log`, `messages` | `> show system disk-space` |
| telemetry / cloud services | `device_telemetry*.log`, `lcaas_agent.log`, `envoy_broker.log` | |

`show_log_system.txt` (the system log) is the cross-daemon timeline: when
you do not know where to look, grep it for the failure minute and it names
the daemon.

Files you can ignore unless you have a reason not to: `global.xml` (the
content database), `regip/reg_ips.xml`, `*.dat` (regex group binaries),
`ui_content/*.js.gz`, `fs_manifest.txt` (a file listing of the whole box),
`req_stats.log` (management-server request accounting),
`last-candidatecfg-audit.xml,v` (RCS history of every *candidate*, tens of
MB), `tmp/cli/logs/sysd_objects_meta.xml` (the whole sysd object tree as
XML — 100 MB on a chassis; `sdb.txt` is the same data as grep-able dotted
keys), `opt/var*/…/log/pan/memdump/hwbuf-*.raw` (100 MB binary hardware
buffer dumps per DP). Two that look like noise but are not: `content_telemetry.log` opens
with a full `--- show system info ---` block (a second copy of the device's
identity and versions), and `show_log_system.txt` (79 MB seen) is the
cross-daemon timeline — grep it, never open it.

## 5. Reading the config

`running-config.xml` is the config in force. Structure:

```
config/
  mgt-config/                  admins, passwords (hashed), roles
  shared/                      shared objects: certificates, server profiles (LDAP/RADIUS/syslog), log settings
  devices/entry[localhost.localdomain]/
    deviceconfig/system/       hostname, DNS, NTP, mgmt IP, Panorama servers
    deviceconfig/setting/      tuning: session timeouts, jumbo frames, ctd, …
    deviceconfig/high-availability/
    network/                   interfaces, virtual routers, IKE gateways, IPsec tunnels, zones, profiles
    vsys/entry[vsys1]/         address/service objects, rulebase (security, nat, pbf, decryption…), GP portal/gateway, auth
```

Panorama-managed devices carry the pushed part in `.merged-running-config.xml`
and the raw push in `opt/pancfg/mgmt/tmp/panorama_pushed/` (`before-` and
`after-sp-imported.xml`). `running-config.xml` alone is then incomplete.

`cfg-audit.xml,v` is an RCS file: each revision is one commit, with author
and timestamp. `rlog`/`co -p` read it, or search `date` headers by hand. It
answers "what changed just before it broke".

`platform.xml` holds the limits PAN-OS actually enforces for this model
(sessions, rules, tunnels, licensed vsys) — compare them with `show session
info` and the object counts rather than trusting a datasheet.

## 6. A reading order that works

1. `show system info` → version, uptime, HA, serial. Uptime shorter than the
   problem's age means a reboot: go to crashes first.
2. `show system files` + `var/log/pan/crashinfo/` → any core dump or crash
   sidecar? The crash time is in the filename
   (`configd-20260305145809-….info`).
3. `show_log_system.txt` around the reported time → which daemon complained.
4. That daemon's log, **including rotations**, around the same minute.
5. The relevant `show` sections (§3) for the current state.
6. The config for the objects the log lines name (rule, gateway, profile).
7. `cfg-audit.xml,v` / `show jobs processed` → what changed, and when.

Keep the device timezone in mind at every step, and remember that a TSF is a
snapshot: counters are *since boot* unless a section says delta.

## 7. Reading an anonymized TSF

An archive produced by this tool has the same layout, the same files, the
same line counts and timestamps; only identifiers changed, consistently:

| you see | it was |
|---|---|
| `100.64.x.y` … `100.127.x.y` | a private (RFC 1918) address |
| `192.0.2.x`, `198.51.100.x`, `203.0.113.x` | a public address |
| `hostNNN.anon.internal`, `hostNNN` | a FQDN / hostname |
| `userNNN` | a username (also the local part of an e-mail) |
| `ZONE-0012`, `RULE-0045`, `ADDR-0003`, `GW-0002`, `OBJ-0100` … | a named config object; the prefix is its category |
| all-digit serial of the same length | a serial number |

The same original value always maps to the same replacement across every
file, so "peer `203.0.113.7` on gateway `GW-0002`" is the same peer and
gateway wherever they appear. Interface names (`ethernet1/1`, `ae1`,
`tunnel.1`), built-in objects (`any`, `trust`, `vsys1`), vendor domains and
netmasks are untouched. **Member names are rewritten with the same
mapping**: the command dump reads `tmp/cli/techsupport_host001_<date>.txt`.
The device's own hostname, devicename, domain and serial are taken from
`show system info` itself, so they are pseudonymized wherever they appear —
including glued with underscores in a file name.

The `*.mapping.json` sidecar reverses every substitution. It is the
customer's identity in one file: it stays with whoever owns the original and
is never sent along with the anonymized archive.

Binary files (`rule-hit-count.bin`, `*.dat`, sqlite DBs, `wtmp`/`btmp`/
`lastlog`, and `sslvpn-task.log*.gz` — a binary record format that embeds the
source IP and username of every GlobalProtect request) are copied through
unchanged; the integrity report lists any that still embed identifiers. With
**redact binaries** — on by default — such a member's payload is replaced by
the one-line marker `[tsf-anonymizer] binary payload redacted…`; the original
is gone from the archive, not hidden, and the verification checks that each
redaction was warranted. Every redacted family has a text twin that is
anonymized normally (`saNN` → `sarNN`, `rule-hit-count.bin` →
`rule-hit-count-db.txt`, `sslvpn-task` → `show_log_globalprotect.txt`),
except `wtmp`/`btmp`/`lastlog`: the admin login history is the one thing an
anonymized archive no longer carries — `show_log_system.txt` and `authd.log`
cover the same question.
