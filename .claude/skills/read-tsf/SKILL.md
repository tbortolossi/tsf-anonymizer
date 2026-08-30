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

Timestamps sort textually within one format, but formats differ per file —
six distinct families on one device; see step 2b before writing a grep.

## Step 2b — how the log files actually read

**One record = one timestamped line, plus untimestamped continuation lines.**
A file often *starts* mid-record (rotation cuts anywhere): the first lines may
have no timestamp — scan down to the first timestamped line before concluding
anything about format. Daemons print startup banners (`*** STARTING DHCPD ***`)
as multi-line blocks under a single timestamp.

Format families (all verified on a real PA-440 TSF — match the file, then
pick the right grep):

| family | example | files |
|---|---|---|
| PAN standard: `YYYY-MM-DD HH:MM:SS.mmm +ZZZZ` | `2026-04-05 05:57:32.225 +0200 Error: pan_cfg…(file.c:647): msg` | most of `var/log/pan/`: configd, authd, sysd, useridd, routed, mprelay, devsrv, ha_agent… The `func(file.c:line):` prefix is grep-able and names the code path. |
| ikemgr-ng: `YYYY:MM:DDTHH:MM:SS.mmm+ZZ:ZZ` | `2026:03:01T15:13:18.024+01:00 [4371-4442] [INFO]: …` | `ikemgr-ng.log`, `keymgr-ng.log` — **colons in the date**: a `2026-03-01` grep finds nothing here. `[pid-tid]` follows. |
| JSON lines | `{"level":"info","time":"2026-03-01T15:13:17.65+01:00","message":"…"}` | `gpsvc.log`, `wifgo*.log`, `gp_broker` parts, `logging-services*.log` — use `jq -r` or grep the `"message"` value; `"level":"error"` filters. |
| syslog, **yearless** | `Mar  1 06:12:39 400 kernel: […] msg` | `var/log/messages`, `show_log_journal.txt` — no year: infer it from the TSF window; day-of-month is space-padded (`Mar  1` = two spaces). |
| audit key=value, **epoch** | `type=USER_AUTH msg=audit(1774665326.812:16547): … acct="x" exe="/usr/bin/su"` | `var/log/audit/audit.log*` — the only time is the epoch inside `audit(…)`: `date -d @1774665326`. |
| nginx access | `IP - - [01/Mar/2026:15:20:33 +0100] "GET /x" 200 …` | `var/log/nginx/*`, `sslvpn-access.log`(text ones), `mgmt_httpd_access.log`. |
| bracketed | `[2026-03-30 00:00:00.001 INF] msg` | plugin logs (`opt/plugins/var/log/pan/plugin-*`). |
| periodic dump | a timestamp line, then a raw command dump (netstat, counters), repeated | `md_out.log` (netstat every few min, records glued without separators), `evtmgr_*_snapshot` (counter tables, few timestamps), `req_stats.log`. Diff two dumps rather than reading one. |

**The monitor logs are the TSF's time machine — sectioned snapshots, not a
stream.** Every ~2–5 min, `mp-monitor.log` and `dp-monitor.log` append blocks
of the form `<timestamp>  --- <section>`:

- `mp-monitor.log` sections: `cpu` (incl. load avg), `memory`,
  `memory_detail`, `processes`/`top_summary`/`pidstat` (per-PID — **a PID
  change between snapshots = daemon restart with no reboot**), `filesystem`,
  `diskstats`, `swapusage`, `conntrack`, `netstat`, `logging_status`,
  `logrcvr_statistics`, `health_check`, `smart`, `env` (temperatures)…
- `dp-monitor.log` sections: `cpu`, `memory`, `processes`, `panio` (DP
  message latency histograms — the congestion evidence), `netstat`,
  `filesystem`, `smart`…

Carve one section's history, or one instant, like this:

```bash
grep -n " --- " var/log/pan/mp-monitor.log | head            # index of snapshots
awk '/--- memory$/{on=1} on&&/^2026.* --- /&&!/--- memory$/{on=0} on' var/log/pan/mp-monitor.log | head -80
sed -n '/^2026-04-05 09:2.* --- /,/^2026-04-05 09:[3-9]/p' var/log/pan/dp-monitor.log   # a time window
```

That is how "what did memory/CPU/processes look like *before* the incident"
gets answered from a snapshot archive — compare the sections across
timestamps instead of reading one block.

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
| **Drops / perf / buffers** | `> show counter global filter delta yes`, `> show running resource-monitor` | `dp-monitor.log`, `> show session info`, `> debug dataplane pool statistics`, `> show zone-protection` | See the buffers/PBP/counters section below. Read `drop`/`error` severities first; the **delta** section says what happens now. `flow_policy_deny`+`tcp_rst_from_self`=policy RST · `flow_fwd_mtu_exceeded`+`ip_df_drop`=MTU in tunnel path (big packets fail, ping works) · `flow_tcp_non_syn` right after failover is EXPECTED. Depleted DP pools drop silently. |
| **Interfaces** | `> show interface all`, `pan_ifmgr.log` | `brdagent.log` (port/ASIC), `l2ctrld.log` | Physical first — it invalidates every higher-layer diagnosis on the path. CRC/FCS on one port=cable/SFP · late collisions=duplex mismatch · `dot1q_tag_err`=VLAN arriving on a port not carrying it. |
| **Disk** | `> show system disk-space`, `df` in techsupport | `logpurger.log`, `messages` | WHICH partition decides the cause: /var/log=logrotate stuck (du≠df = deleted-fd) or forgotten debug level · /opt/panrepo=old images (safe cleanup) · /opt/panlogs=at quota by design, only purge *errors* matter · root full=the dangerous one (commits fail). Cores on disk = pivot to crash, don't delete them. |
| **Routing** | `routed.log` or `frr_export.log`+`etc/frr/` | `> show routing route` / `> show advanced-routing …` | Advanced-routing engine = FRR; legacy = routed. Check which one owns the config. |
| **Commit / config** | `configd.log`, `commit_stats.log`, `show_log_config.txt` | `cfg-audit.xml,v` | `commit_stats.log` has per-phase durations (Jobid/Start/Fin blocks). |
| **Content / AV updates** | `paninstaller_content.log`, `contentd.log` | `opt/pancfg/mgmt/global/*info.xml` | Correlate the update **time** with the symptom start before blaming it. |
| **Panorama** | `devsrv.log`, `ms.log` | `opt/pancfg/mgmt/tmp/panorama_pushed/` | `running-config.xml` alone is incomplete on managed devices — use `.merged-running-config.xml`. |

\* alias rule of step 2 applies.

## Buffers, packet-buffer protection and counters — the silent-drop toolkit

Several drop causes generate **no traffic-log entry**: zone protection, PBP,
NAT pool exhaustion (`nat_port_alloc_fail`), a full session table. When policy
and routing look correct but the customer reports loss, counters and the
sections below are the only evidence.

**Buffer / descriptor utilization** — in the techsupport txt,
`> show running resource-monitor` repeats per second / minute / hour / day /
week, each with a `Resource utilization (%)` block: `session`,
`packet buffer`, `packet descriptor`, `sw tags descriptor` (larger platforms
print `packet descriptor (on-chip)` per DP/slot — the hardware ingress
descriptors). Read **maximum** rows, not averages:

```bash
grep -A5 "^packet buffer (maximum):" tmp/cli/techsupport_*.txt
grep -A5 "descriptor (maximum):" tmp/cli/techsupport_*.txt
```

Interpretation: descriptor near 100 % with modest CPU = ingress congestion —
packets are dropped at the wire while every core looks idle; packet buffer
sustained > 80 % = imminent PBP/RED; a **baseline** > 40 % at peak = the
platform is undersized, not an incident. `> debug dataplane pool statistics`
gives the instant view: `Packet Buffers : free/total` against
`Low free buffer limit` (free approaching the limit = exhaustion), and a
non-zero `Depleted` column in the segment table.

**Packet Buffer Protection (PBP)** — two phases, three counters:

- `pkt_buf_protect_red` — Phase 1 (global): RED applied to the offending
  session as the buffer crosses the Activate threshold. Any non-zero rate =
  buffer under sustained pressure; intermittent loss + retransmits that
  mimics upstream congestion.
- `pkt_buf_protect_discard` — Phase 2 (per-zone): the offending session is
  torn down. Long-lived high-bandwidth transfers reset without warning.
- `pkt_buf_protect_block_ip` — Phase 2: the **source IP is blocked entirely**
  (default 3600 s), silently. **The classic escalation: the blocked source is
  a NAT device (site router, proxy) → the whole site loses everything, with
  zero log evidence.** On "everyone in the office lost internet at once",
  check this counter before anything else. Live-device follow-ups (usually
  NOT captured in the TSF): `show session packet-buffer-protection`,
  `show running resource-monitor ingress-backlogs` (sessions holding ≥ 2 % of
  on-chip descriptors), `clear session packet-buffer-protection`.

Buffer-exhaustion counters when PBP is off or overwhelmed:
`pkt_alloc_fail*`, `buf_alloc_fail`, `hw_buf_alloc_fail`, `flow_rcv_err_pkt`,
`packets_dropped_buffer`, and `pkt_recv_skip_inflight` (processing backlog too
deep — DP overload even at moderate CPU). Random, flow-unmappable loss is the
tell.

**Zone protection** — `> show zone-protection` lists, per zone and mechanism,
`enabled: yes/no` and `packet dropped: N`. Non-zero drops here are silent by
design. `tcp-reject-non-syn` drops are routine after a failover (unsynced
sessions) — sustained means asymmetric routing. Flood/recon counters firing:
decide legitimate burst (internal scanner, backups → raise threshold or use a
classified rule) vs attack (block the source) before touching thresholds.

**Counter method** — `> show counter global` appears twice: raw (since boot)
and `filter delta yes` (a few seconds — what happens *now*; rate column ≠ 0
is the live signal). Sort by severity `drop`/`error` first, then read pairs:
`flow_tcp_non_syn` ≈ `flow_tcp_non_syn_drop` = 100 % of stateless TCP
dropped; `tcp_drop_packet` + `tcp_exceed_flow_seg_limit` = out-of-order queue
overflow (asymmetry/reordering upstream); `flow_dos_*` = zone/DoS protection
acting (see above). A counter name is not self-explanatory — when unsure,
grep the same name in the raw section for its description column.

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
