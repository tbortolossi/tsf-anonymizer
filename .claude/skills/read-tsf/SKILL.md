---
name: read-tsf
description: >
  Analyze a PAN-OS tech support file (TSF) with shell tools. Use whenever the
  task involves a techsupport .tgz or an extracted TSF tree — diagnosing a
  firewall problem (VPN, HA, GlobalProtect, crash, CPU, drops…), finding the
  right log for a symptom, or answering "what happened on this device".
  Distilled from TAC-MAN's tsf-agent (file map, log aliases, L3 doctrine).
---

# Reading a PAN-OS tech support file

A TSF is a gzipped tar (100–400 MB, ~1.2 GB extracted, ~500 files): the device
configuration, the daemon logs with their rotations, and the output of several
hundred `show`/`debug` commands captured at generation time. The full layout
and per-file map is in [docs/TSF-GUIDE.md](../../../docs/TSF-GUIDE.md); this
skill is the working method.

## Step 0 — extract and anchor yourself

```bash
mkdir tsf && tar xzf <file>.tgz -C tsf && chmod -R u+rwX tsf && cd tsf
ls tmp/cli/                          # techsupport_<model>_<date>.txt = the command dump
grep -A3 "^> show clock" tmp/cli/techsupport_*.txt
grep -A25 "^> show system info" tmp/cli/techsupport_*.txt | head -30
```

Anchor on three facts before anything else:

1. **Device time and timezone** (`show clock`, e.g. `Sun Apr 5 09:36:57 CEST 2026`).
   Every log line in the TSF is in that timezone with **no offset written**.
   Convert before correlating with anything external.
2. **PAN-OS version, model, serial, uptime, HA state** (`show system info`).
   Uptime shorter than the problem's age = there was a reboot → check crashes
   first, whatever the reported symptom.
3. **Generation time** (filename + `show clock`): counters and `show` output
   are a snapshot of that moment; logs are the history before it.

Real TSFs ship files in mode `0000` — hence the `chmod`. Files may hold
Latin-1 bytes; add `-a` to grep or decode with `errors="surrogateescape"`.

## Step 1 — the reading order that works

1. `show system info` → version, uptime, HA.
2. Crash evidence: `var/log/pan/crashinfo/*.info` (the crash instant is in the
   **filename** — `configd-20260305145809-….info` — never the mtime, which
   extraction rewrites), `grep -A15 "^> show system files" tmp/cli/techsupport_*.txt`,
   `opt/panrepo/logs/reboot.log` (reason + timestamp per reboot).
3. `tmp/cli/logs/show_log_system.txt` around the failure minute — the
   cross-daemon timeline. When you don't know where to look, this names the
   daemon that complained.
4. That daemon's log under `var/log/pan/`, **including rotations** (step 2 trap).
5. The relevant `show` sections for current state (step 3 table).
6. The config for the objects the log lines name.
7. What changed: `grep -B2 -A8 "^> show jobs processed" tmp/cli/techsupport_*.txt`
   (commit history), `opt/pancfg/mgmt/audit/cfg-audit.xml,v` (RCS history of
   every commit — `grep -n "^date" `, or `co -p` if RCS tools exist).

## Step 2 — logs: aliases and rotations (the two classic misses)

**Some daemons have two log names and the newest is the live one.** On
PAN-OS 11.1+ IKE writes `ikemgr-ng.log` while the legacy `ikemgr.log` stays
present and idle — reading only the legacy name reports "no IKE errors" about
a firewall whose tunnels are down. Pairs: `ikemgr`/`ikemgr-ng`,
`keymgr`/`keymgr-ng`, `dnsproxyd`/`dnsproxy_go`/`dns-go-agent`. Always:

```bash
ls var/log/pan/ | grep -E "^ikemgr|^keymgr|^dnsproxy"   # see what exists, read -ng first
```

**The failure window is often only in a rotation.** `<d>.log` is live,
`<d>.log.old` / `.1` / `.2` older, `.gz` compressed. A chatty daemon rotates
the interesting hour away before the TSF is generated. Search them all:

```bash
zgrep -h "<pattern>" var/log/pan/ikemgr-ng.log* var/log/pan/ikemgr.log* 2>/dev/null | sort | head -50
```

Timestamps sort textually within one format, but formats differ per file
(`2026-04-07 10:00:01`, `2026/04/05 09:40:34`, `Apr  7 10:00:09` — yearless!,
`ikemgr-ng`: `2026:03:09T…` with colons in the date). Epoch-ms values
(13 digits) appear inline. `md_out.log` glues records without separators.

## Step 3 — symptom → files → what to grep

`sdb.txt` (the sysd state database) and `techsupport_*.txt` are useful for
every symptom. Then, per domain (P0 files first — this is tsf-agent's own
priority map):

| symptom | read first | then | grep for / interpret |
|---|---|---|---|
| **VPN site-à-site** | `ikemgr-ng.log`* | `keymgr*.log`, `> show vpn ike-sa / ipsec-sa / flow` | `failed to get sainfo`=Phase2 proxy-ID mismatch · `no proposal chosen`=no common crypto · `AUTHENTICATION_FAILED`=PSK (case-sensitive!) or cert · `TS_UNACCEPTABLE`=IKEv2 selector mismatch · SPI mismatch=peer rebooted, stale SA · `DPD: peer dead`=connectivity, NOT negotiation. Phase 1 must establish before any Phase 2 diagnosis. |
| **HA / failover** | `ha_agent.log`, `> show high-availability all` | `path-monitoring`, `state-synchronization`, `brdagent.log` | Classify the cause: heartbeat_loss (HA1 flap/peer down) · link_monitoring (NIC → check failure-condition any/all) · path_monitoring · **commit within 120 s of failover = spurious** (commits pause heartbeats 5–15 s) · process_restart. Preemption disabled = no auto-failback. |
| **GlobalProtect** | `gpsvc.log`, `show_log_globalprotect.txt`, `gp_broker.log` | `sslvpn-access.log`, `sslvpn_ngx_error.log`, `rasmgr.log` | Split by WHERE the client stops: portal (config fetch) → auth → gateway (tunnel) → data. `Authentication failed` in gpsvc = **not a GP problem**, pivot to authd. Portal-vs-gateway auth-profile mismatch = auth OK then fails seconds later. |
| **Auth** | `authd.log`, `useridd.log` | `show_log_system.txt`, `sslmgr.log` (certs) | LDAP `rc=49`=bad bind credentials; RADIUS timeouts; SAML clock skew. |
| **User-ID** | `useridd.log`, `distributord.log` | `> show user ip-user-mapping…` | Identification ≠ authentication: nobody fails a login, policy just mis-applies / user shows `unknown`. A login failing = auth domain instead. |
| **Crash / reboot** | `crashinfo/`, `reboot.log`, `sysd.log` | `messages`, `mce.log`, `bios.log`, `history.log` | `grep -E "panic|oops|segfault|watchdog|Killed process"`. PID change in `mp-monitor.log` = daemon restart without reboot. **After any upgrade, check for crashes even if the symptom isn't crash-shaped.** |
| **CPU** | `dp-monitor.log`, `mp-monitor.log`, `> show running resource-monitor` | `var/log/sa/sar*` (31-day history) | DP CPU = traffic-side (sessions, decryption, App-ID); MP CPU = reports/logging/configd. DP > 80 % sustained 3+ snapshots = critical. Correlate spikes with commits/content updates. |
| **Memory** | `mp-monitor.log`, `> show system resources` | `grep -E "Out of memory|oom-killer"` | Growth across 3+ snapshots is the signal, never one reading. Linux cache ≠ pressure. LEAK (one RSS rising) vs LOAD (tracks sessions/tunnels) vs steady-high (benign). A leaking daemon is a future-crashing daemon. |
| **Drops / perf** | `> show counter global filter delta yes` | `dp-monitor.log`, `> show session info`, `> debug dataplane pool statistics` | Read `drop`/`error` severities first; the **delta** section says what happens now. `flow_policy_deny`+`tcp_rst_from_self`=policy RST · `flow_fwd_mtu_exceeded`+`ip_df_drop`=MTU in tunnel path (big packets fail, ping works) · `flow_tcp_non_syn` right after failover is EXPECTED. Depleted DP pools drop silently. |
| **Interfaces** | `> show interface all`, `pan_ifmgr.log` | `brdagent.log` (port/ASIC), `l2ctrld.log` | Physical first — it invalidates every higher-layer diagnosis on the path. CRC/FCS on one port=cable/SFP · late collisions=duplex mismatch · `dot1q_tag_err`=VLAN arriving on a port not carrying it. |
| **Disk** | `> show system disk-space`, `df` in techsupport | `logpurger.log`, `messages` | WHICH partition decides the cause: /var/log=logrotate stuck (du≠df = deleted-fd) or forgotten debug level · /opt/panrepo=old images (safe cleanup) · /opt/panlogs=at quota by design, only purge *errors* matter · root full=the dangerous one (commits fail). Cores on disk = pivot to crash, don't delete them. |
| **Routing** | `routed.log` or `frr_export.log`+`etc/frr/` | `> show routing route` / `> show advanced-routing …` | Advanced-routing engine = FRR; legacy = routed. Check which one owns the config. |
| **Commit / config** | `configd.log`, `commit_stats.log`, `show_log_config.txt` | `cfg-audit.xml,v` | `commit_stats.log` has per-phase durations (Jobid/Start/Fin blocks). |
| **Content / AV updates** | `paninstaller_content.log`, `contentd.log` | `opt/pancfg/mgmt/global/*info.xml` | Correlate the update **time** with the symptom start before blaming it. |
| **Panorama** | `devsrv.log`, `ms.log` | `opt/pancfg/mgmt/tmp/panorama_pushed/` | `running-config.xml` alone is incomplete on managed devices — use `.merged-running-config.xml`. |

\* alias rule of step 2 applies.

## Step 4 — the config

`opt/pancfg/mgmt/saved-configs/running-config.xml` is the config in force
(`.merged-running-config.xml` if Panorama-managed; the raw push sits in
`panorama_pushed/before|after-sp-imported.xml`). Structure and grep entry
points: `docs/TSF-GUIDE.md` §5. Two specifics:

- `opt/pancfg/mgmt/devices/*/platform.xml` = the limits PAN-OS **enforces**
  (max sessions, tunnels, rules) — compare with `show session info` rather
  than trusting a datasheet.
- Candidate configs embed the vendor App-ID catalog under `<config><global>`
  — thousands of `<entry name="Apple">…` that are Palo Alto content, not
  customer objects. Ignore that subtree.

## Traps that produce confident wrong answers

- **"No errors in the log" while reading the wrong file**: check the `-ng`
  alias and the rotations before concluding (step 2).
- **An absent file ≠ a healthy subsystem**; an empty grep ≠ nothing happened
  (the window may be rotated away, or that daemon logs elsewhere).
- **Counters are since-boot** unless the section says delta.
- **mtime is meaningless** post-extraction; dates live in filenames and line
  content.
- **Huge vendor files** — `updates/*/global.xml` (37 MB App-ID DB),
  `regip/reg_ips.xml`, `*.dat`, `fs_manifest.txt`, `req_stats.log` — are
  almost never the answer; don't burn context reading them.
- **Binary files** (`rule-hit-count.bin`, `wtmp`, `var/log/sa/sa*`,
  `sslvpn-task.log`) need `grep -a` / `strings`, or the matching text export
  (`sar*`, `rule-hit-count-db.txt`).

## Anonymized TSFs

A TSF produced by this repo's anonymizer keeps layout, line counts,
timestamps, counters, interface names and built-ins; identifiers are replaced
consistently (same original → same pseudonym everywhere): `100.64.x.y` was a
private IP, `192.0.2.x`/`198.51.100.x`/`203.0.113.x` public, `hostNNN[.anon.internal]`
a hostname, `userNNN` a user, `ZONE-0012`/`RULE-0045`/`GW-0002`… named objects
(prefix = category), same-length digits starting `9` a serial. Correlation
still works — "peer `203.0.113.7` on `GW-0002`" is the same peer everywhere.
The `*.mapping.json` sidecar reverses it and must never travel with the
anonymized archive.
