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
and per-file map is in [TSF-GUIDE.md](TSF-GUIDE.md); this
skill is the working method.

Every path and grep below was re-checked against ten real TSFs — PA-440,
PA-1420, PA-3220 (×2), PA-3410, PA-5250 (×2), PA-5430, PA-7050, PA-7080, on
PAN-OS 10.2.9 → 12.1.4. Where a file exists only on some of them the
qualifier says so (`12.x`, `PA-3200 family`, `chassis`); an unqualified path
was present on all ten.

## Step 0 — extract and anchor yourself

```bash
mkdir tsf && tar xzf <file>.tgz -C tsf && chmod -R u+rwX tsf && cd tsf
ls tmp/cli/                          # techsupport_<devicename>_<YYYYMMDD>_<HHMM>.txt = the command dump
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
The command dump is named after the **device** (hostname as the customer set
it), never the model — verified on ten real TSFs; the model is on the
`model:` line of `show system info`. Two wrinkles: PAN-OS may **drop a
hyphen** from the hostname when it builds the name (`fw-dc1` →
`techsupport_fwdc1_…`, seen on three of ten), so glob `techsupport_*.txt`
and read the hostname from `show system info`, never from the file name; and
a hostname left at its default *is* the model name (`PA-440` →
`techsupport_PA440_…`), which only looks like the exception. If the command
dump is truncated or missing, `var/log/pan/content_telemetry.log` (present
on nine of ten — not on a PA-5250 11.2) opens with a full
`--- show system info ---` block — a second copy of the device's identity
and versions.

A fourth fact worth one grep before diving into any symptom:
`grep -A40 "^> request license info" tmp/cli/techsupport_*.txt` — an
**expired licence** (Threat Prevention, URL, GlobalProtect, support…)
explains many "it stopped working on <date>" reports, and no daemon log
says so as plainly.

## Step 1 — the reading order that works

1. `show system info` → version, uptime, HA.
2. Crash evidence: `var/cores/crashinfo/*.info` — **not** under
   `var/log/pan/`; the directory exists only once something crashed (an
   empty `var/cores/` = no MP crash), and on a chassis each dataplane has its
   own: `opt/var/s<slot>/dp<n>/cores/crashinfo/` (PA-7000),
   `opt/var.dp<n>/cores/` (PA-5200). The crash instant and the process are
   in the **filename** — `routed-20260109122837-11.1.10-h1.info`,
   `all_pktproc_3-<stamp>-<version>.info` for a DP packet-processor crash —
   never the mtime, which extraction rewrites. Then
   `grep -A15 "^> show system files" tmp/cli/techsupport_*.txt` (it lists
   `/opt/panlogs/cores/` and `/var/cores/` as seen on the box) and
   `opt/panrepo/logs/reboot.log` (reason + timestamp per reboot — `SYSTEM
   REBOOT [CLI Initiated at …]`, `[external power cycle …]`, `[md initiated
   dataplane restarts exhausted …]`; absent on one 10.2 PA-7050). `bios.log`,
   `history.log` and `swm.log` (software manager) sit next to it.
3. `tmp/cli/logs/show_log_system.txt` around the failure minute — the
   cross-daemon timeline. When you don't know where to look, this names the
   daemon that complained.
4. That daemon's log under `var/log/pan/`, **including rotations** (step 2 trap).
5. The relevant `show` sections for current state (step 3 table).
6. The config for the objects the log lines name.
7. What changed: `grep -B2 -A8 "^> show jobs processed" tmp/cli/techsupport_*.txt`
   (commit history), `opt/pancfg/mgmt/audit/cfg-audit.xml,v` (RCS history of
   every commit — `grep -n "^date" `, or `co -p` if RCS tools exist), and
   `var/log/pan/dagger.log` for **what was run** from the CLI/API and when:
   one `OPCMD: handler "<command>"` / `finish handler …` pair per operational
   command, timestamped — `grep -h "OPCMD" var/log/pan/dagger.log*` around
   the failure minute says whether a human restarted, cleared or tested
   something just before it broke.

## Step 2 — logs: aliases and rotations (the two classic misses)

**Some daemons have two log names and the newest is the live one.** On
PAN-OS 11.1+ IKE writes `ikemgr-ng.log` while the legacy `ikemgr.log` stays
present and idle — reading only the legacy name reports "no IKE errors" about
a firewall whose tunnels are down. Pairs: `ikemgr`/`ikemgr-ng` and
`keymgr`/`keymgr-ng` (11.1+; on 10.2 only the legacy names exist and they
are live, in PAN standard format), `dnsproxyd`/`dnsproxy_go`/`dns-go-agent`
(the `go` pair appears on 11.2+; 11.1 has `dnsproxyd.log` alone). Always:

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
| ikemgr-ng: `YYYY:MM:DDTHH:MM:SS.mmm+ZZ:ZZ` | `2026:03:01T15:13:18.024+01:00 [4371-4442] [INFO]: …` | `ikemgr-ng.log`, `keymgr-ng.log` — **colons in the date**: a `2026-03-01` grep finds nothing here. `[pid-tid]` follows. (10.2's `ikemgr.log` is PAN standard.) |
| JSON lines | `{"level":"info","time":"2026-03-01T15:13:17.65+01:00","message":"…"}` | `gpsvc.log`, `wifgo*.log`, `gp_broker` parts, `logging-services*.log` — use `jq -r` or grep the `"message"` value; `"level":"error"` filters. |
| syslog, **yearless** | `Mar  1 06:12:39 <host> kernel: […] msg` | `var/log/messages`, `tmp/cli/logs/show_log_journal.txt` (12.x only) — no year: infer it from the TSF window; day-of-month is space-padded (`Mar  1` = two spaces). |
| audit key=value, **epoch** | `type=USER_AUTH msg=audit(1774665326.812:16547): … acct="x" exe="/usr/bin/su"` | `var/log/audit/audit.log*` — the only time is the epoch inside `audit(…)`: `date -d @1774665326`. |
| nginx access | `IP - - [01/Mar/2026:15:20:33 +0100] "GET /x" 200 …` | `var/log/nginx/{access,error,api_metrics,l3svc_access}.log`. Two look-alikes with their own shape: `mgmt_httpd_access.log` is **status-first, no client IP** — `200 [01/Mar/2026:15:14:17 +0100] 0 26 /robots.txt "python-requests/2.25.1"`; `sslvpn-access/sslvpn-access.log` (a *directory*, present only when GP is configured) is `IP   [2026-03-01 15:47:36.311249739 +0100 CET] POST /global-protect/prelogin.esp HTTP/1.1 153 200 595, taskid 1`. |
| bracketed | `[2026-03-30 00:00:00.001 INF] msg` | dated plugin logs (`opt/plugins/var/log/pan/plugin-adem-YYYYMMDD.log`); `plugin_dlp.log` / `plugin_client.log` next to them are PAN standard. |
| periodic dump | a timestamp line, then a raw command dump (netstat, counters), repeated | `md_out.log` (netstat every few min, records glued without separators), `evtmgr_*_snapshot` (counter tables, few timestamps), `req_stats.log`. Diff two dumps rather than reading one. |

**The monitor logs are the TSF's time machine — sectioned snapshots, not a
stream.** Every ~2–5 min, `mp-monitor.log` and `dp-monitor.log` append blocks
of the form `<timestamp>  --- <section>`:

- `mp-monitor.log` sections: `cpu` (incl. load avg), `memory`,
  `memory_detail`, `processes`/`top_summary`/`top`/`pidstat` (per-PID — **a
  PID change between snapshots = daemon restart with no reboot**),
  `filesystem`, `diskstats`, `swapusage`, `conntrack`, `netstat`,
  `netstat_stats`, `logging_status`, `logrcvr_statistics`, `smart`, `env`
  (temperatures), `fast_logrotate`, `userid_opcmd_stats`, `health_check`
  (12.x)… The most frequent block by far is `fvif_stats` (interface
  counters, several per snapshot) — exclude it when counting snapshots.
- `dp-monitor.log` sections: `cpu`, `memory`, `processes`, `top`, `panio`
  (DP message latency histograms — the congestion evidence) and
  `panio_infreq`, `bcm_g_cntr_stats` / `dpc_nica_stats` (switch-chip and NIC
  counters), `logrcvr_statistics`, `netstat`, `netstat_stats`, `filesystem`,
  `smart`… Same set on a PA-440, a PA-3220 and a PA-7080 dataplane.

Carve one section's history, or one instant, like this:

```bash
grep -n " --- " var/log/pan/mp-monitor.log | head            # index of snapshots
awk '/--- memory$/{on=1} on&&/^2026.* --- /&&!/--- memory$/{on=0} on' var/log/pan/mp-monitor.log | head -80
sed -n '/^2026-04-05 09:2.* --- /,/^2026-04-05 09:[3-9]/p' var/log/pan/dp-monitor.log   # a time window
```

That is how "what did memory/CPU/processes look like *before* the incident"
gets answered from a snapshot archive — compare the sections across
timestamps instead of reading one block.

**Multi-DP and CP — chassis platforms have more than one of everything.**
A PA-400/800/1400/3400 or VM has one MP and one DP: `var/log/pan/dp-monitor.log`
is *the* dataplane — and so does a **PA-5400** (5410–5450, family `5400f`),
verified on a real PA-5430: no `opt/var.dp*` at all. The **PA-3200 family**
(3220/3250/3260) is single-DP too but keeps that dataplane's logs under
**`opt/dpfs/var/log/pan/`** — `dp-monitor.log` and eight rotations,
`bcm.log`, `brdagent.log`, `bfd.log`, `pan_task_<n>.log`, `md_out.log`
(~57 files) — and has **no** `var/log/pan/dp-monitor.log` at all (two real
PA-3220, 11.1.6 and 11.1.14); its DP serial console is
`var/log/pan/dataplane-console-output.log`. PA-5200/PA-7000 (and older 5000)
have several planes:

- **Each dataplane logs under its own root**: `opt/var.dp0/log/pan/dp-monitor.log`,
  `opt/var.dp1/…`, `opt/var.dp2/…` on a PA-5200. A PA-7000 chassis nests the
  **slot** as well: `opt/var/s<slot>/dp<n>/log/pan/` — a real PA-7080 (family
  `7000b`) had eleven populated slots (`s1`…`s11`, four DPs each, ~95 files
  per DP), and `sysd.log`/`sdb.txt` name components `s<slot>.dp<n>`
  (`cfg.net.s6.eth2@252.acl` = slot 6, interface eth2, VLAN 252). Each DP
  root may carry `log/pan/memdump/hwbuf-*.raw` — 100 MB hardware-buffer dumps,
  binary, only for a buffer post-mortem. A slot holds more than dataplanes:
  `opt/var/s<slot>/cp/` (the card's control processor), and on a PA-7000 the
  **log processing cards** `opt/var/s<slot>/lfp<n>/log/pan/` — `logrcvr.log`,
  `syslog-ng.log` (150 MB seen), `lfp-monitor.log` (same sectioned-snapshot
  format as `dp-monitor.log`), `evtmgr_logrcvr_lfp<n>_snapshot`. On a
  chassis, a log-forwarding or log-receiver problem lives *there*, not in
  `var/log/pan/logrcvr.log`. Always `ls -d opt/dpfs opt/var.dp* opt/var/s*/dp* opt/var/s*/lfp*` first, and
  analyse **per plane, never the aggregate** — on a PA-7000 the classic
  finding is one line card at 90 % while the others idle (traffic imbalance),
  invisible in any average. Do not assume which planes exist from the model:
  tsf-agent's note said a PA-5250 skips dp1, but a real PA-5250 on 11.2 had
  `opt/var.dp0`, `opt/var.dp1` and `opt/var.dp2` all populated (~80 files
  each: `dp-monitor.log` + rotations, `dp-sessperf_mon.log`, `brdagent.log`,
  `bfd.log`, `cgroups*.log`). `ls -d opt/var.dp*` is the only reliable answer;
  an empty plane directory is still worth a look before calling it normal.
- **`cp-monitor.log`** exists only on platforms with a dedicated
  control-plane processor: `opt/var.cp/log/pan/cp-monitor.log` on a
  PA-5200, **one per slot** at `opt/var/s<slot>/cp/log/pan/cp-monitor.log`
  on a PA-7000 — never under `var/log/pan/`. Same sectioned-snapshot format
  (`cpu`, `memory`, `processes`, `cp_stats`, `fabric_traffic_stats`,
  `bcm_shcmd_stats`, `pci_dma`, `softnet`, `ifconfig`…); it tracks the MP↔DP
  plumbing: the `cp_stats` block (`sw.mprelay.s1.cp.platform: { netmsg: {
  errors: { acl_delete, arp_delete, arp_update, … }`) is `netmsg` stats vs
  **errors** (ARP/MAC sync between MP and DP — `arp_delete` errors ≫ stats =
  MP/DP desync; `arp_update` errors = DP ARP table full), `ifconfig` TX/RX
  errors on the internal CP interfaces (config-push and sync failures).
  Absent on single-chip platforms by design — not a gap. The CP root also
  holds the switch-fabric logs (`bcm.log`, `bcm_cmd.log` — Broadcom ASIC
  commands and errors), `cp-telemetry.log`, and
  `dataplane<n>-console-output.log`, the serial console of each DP as seen
  from the CP. The MP side keeps the console of the whole card:
  `var/log/pan/controlplane-console-output.log` on a PA-5200 (`N0.LMC1
  Configuration Completed: 4096 MB` = memory init at boot),
  `var/log/pan/slot<n>-console-output.log` and `fpp-console-output.log`
  (the fabric card) on a PA-7000. Single-chip platforms have no console log
  except the PA-3200's `dataplane-console-output.log`.
- **The command dump repeats every dataplane command per DP.** On a chassis
  each per-DP block opens with `> set system setting target-dp s<slot>dp<n>`
  — 98 blocks on a PA-7050/7080, 12 on a PA-5250 — so `grep -c "^> show
  session info"` returning 49 is the layout, not a corrupt file. Index the
  blocks with `grep -n "^> set system setting target-dp" tmp/cli/techsupport_*.txt`
  and read the one for the plane you care about; `> show running
  resource-monitor` is a single header whose output carries `DP s1dp0:`
  sub-blocks instead. The `packet descriptor (on-chip)` rows appear on the
  ASIC-fronted families only (PA-3200, 5200, 7000) — their absence on a
  400/1400/3400/5400 is normal.
- `sysd.log` names components per plane (`s1.dp0`, `s1.mp`), and
  `show running resource-monitor` in the techsupport txt repeats its blocks
  per slot/DP on a chassis — check which DP a block belongs to before
  comparing numbers. MIPS-based DPs (5200/7000) at 80 % are more saturated
  than x86 at 80 % — lower per-core headroom.

## Step 3 — symptom → files → what to grep

`sdb.txt` (the sysd state database, `tmp/cli/logs/`) and `techsupport_*.txt`
are useful for every symptom. `sdb.txt` is a flat dump of dotted keys —
`sys.s1.info.model: PA-440`, `sys.s1.dp0.*`, HA/hardware/version state —
so `grep '^sys\.' sdb.txt | grep -i <topic>` answers "what does the box think
its own state is" without parsing anything. Then, per domain (P0 files first
— this is tsf-agent's own priority map):

| symptom | read first | then | grep for / interpret |
|---|---|---|---|
| **VPN site-à-site** | `ikemgr-ng.log`* | `keymgr*.log`, `> show vpn ike-sa / ipsec-sa / flow` | `failed to get sainfo`=Phase2 proxy-ID mismatch · `no proposal chosen`=no common crypto · `AUTHENTICATION_FAILED`=PSK (case-sensitive!) or cert · `TS_UNACCEPTABLE`=IKEv2 selector mismatch · SPI mismatch=peer rebooted, stale SA · `DPD: peer dead`=connectivity, NOT negotiation. Phase 1 must establish before any Phase 2 diagnosis. |
| **HA / failover** | `ha_agent.log`, `> show high-availability all` | `path-monitoring`, `state-synchronization`, `brdagent.log`; `saved-configs/.ha-remote-rc.xml` = the **peer's** running config, for a config-sync mismatch (`diff <(xmllint --format running-config.xml) <(xmllint --format .ha-remote-rc.xml)`) | Classify the cause: heartbeat_loss (HA1 flap/peer down) · link_monitoring (NIC → check failure-condition any/all) · path_monitoring · **commit within 120 s of failover = spurious** (commits pause heartbeats 5–15 s) · process_restart. Preemption disabled = no auto-failback. |
| **GlobalProtect** | `gpsvc.log`, `show_log_globalprotect.txt` (one row per portal/gateway event — columns: time, gateway/portal, status, event, region, `domain\user`; can be the biggest text file of the TSF, 64 MB seen: grep it by user or by status, never open it), `gp_broker.log` | `sslvpn-access/sslvpn-access.log` (+ `.N.gz` rotations — a **directory** that exists only when a portal/gateway is configured; the `sslvpn-task.log*` beside it are binary), `sslvpn_ngx_error.log`, `rasmgr.log` | Split by WHERE the client stops: portal (config fetch) → auth → gateway (tunnel) → data. `Authentication failed` in gpsvc = **not a GP problem**, pivot to authd. Portal-vs-gateway auth-profile mismatch = auth OK then fails seconds later. |
| **Auth** | `authd.log`, `useridd.log` | `show_log_system.txt`, `sslmgr.log` (certs) | LDAP `rc=49`=bad bind credentials; RADIUS timeouts; SAML clock skew. **An exposed GP portal is brute-forced**: `grep -c "failed authentication for user" tmp/cli/logs/show_log_system.txt` then `grep -o "for user '[^']*'" … \| sort \| uniq -c \| sort -rn \| head` — guessed names (`error`, `request`, `port`, `cli`, `usr`, `test`, `admin`) and one source IP per burst are a scanner, not a customer problem; the `From:` IP of the same lines in `authd.log` says where it comes from. Real users fail with their real names, a few times, from a few IPs. |
| **User-ID** | `useridd.log`, `distributord.log` | `> show user ip-user-mapping-mp all` (the MP's table), `> show user user-id-agent statistics` | Identification ≠ authentication: nobody fails a login, policy just mis-applies / user shows `unknown`. A login failing = auth domain instead. |
| **Crash / reboot** | `var/cores/crashinfo/` (per DP on a chassis, step 1), `opt/panrepo/logs/reboot.log`, `sysd.log` | `messages`, `mce.log` (not on every model), `opt/panrepo/logs/{bios,history,swm}.log`, the console logs (step 2b) | `grep -E "panic|oops|segfault|watchdog|Killed process"`. PID change in `mp-monitor.log` = daemon restart without reboot. **After any upgrade, check for crashes even if the symptom isn't crash-shaped.** |
| **CPU** | `dp-monitor.log`, `mp-monitor.log`, `> show running resource-monitor` | `var/log/sa/sar*` (31-day history) | DP CPU = traffic-side (sessions, decryption, App-ID); MP CPU = reports/logging/configd. DP > 80 % sustained 3+ snapshots = critical. Correlate spikes with commits/content updates. |
| **Memory** | `mp-monitor.log` (`memory`, `memory_detail`, `top_summary`/`pidstat` per PID) | `grep -E "Out of memory\|oom-killer" var/log/messages*` — `> show system resources` is **not** in the command dump on any of ten TSFs (10.2 → 12.1); it is a live-device command, the monitor log is its history | Growth across 3+ snapshots is the signal, never one reading. Linux cache ≠ pressure. LEAK (one RSS rising) vs LOAD (tracks sessions/tunnels) vs steady-high (benign). A leaking daemon is a future-crashing daemon. |
| **Drops / perf / buffers** | `> show counter global filter delta yes`, `> show running resource-monitor` | `dp-monitor.log`, `> show session info`, `> debug dataplane pool statistics`, `> show zone-protection` | See the buffers/PBP/counters section below. Read `drop`/`error` severities first; the **delta** section says what happens now. `flow_policy_deny`+`tcp_rst_from_self`=policy RST · `flow_fwd_mtu_exceeded`+`ip_df_drop`=MTU in tunnel path (big packets fail, ping works) · `flow_tcp_non_syn` right after failover is EXPECTED. Depleted DP pools drop silently. |
| **Interfaces** | `> show interface all`, `pan_ifmgr.log` | `brdagent.log` (port/ASIC), `l2ctrld.log`, `> show system environmentals` (temperature, fans, PSU — a port that flaps with a failed fan or PSU is a hardware case) | Physical first — it invalidates every higher-layer diagnosis on the path. CRC/FCS on one port=cable/SFP · late collisions=duplex mismatch · `dot1q_tag_err`=VLAN arriving on a port not carrying it. |
| **Disk** | `> show system disk-space`, `> show system logdb-quota` (per-log-type quota vs usage — a log type at 100 % is purging by design, not full) | `logpurger.log`, `messages` | WHICH partition decides the cause: /var/log=logrotate stuck (du≠df = deleted-fd) or forgotten debug level · /opt/panrepo=old images (safe cleanup) · /opt/panlogs=at quota by design, only purge *errors* matter · root full=the dangerous one (commits fail). Cores on disk = pivot to crash, don't delete them. |
| **Routing** | `routed.log` or `var/log/pan/frr/` + `etc/frr/` | `> show routing route` / `> show advanced-routing …`, `bfd.log` | Advanced-routing engine = FRR (`advanced-routing: on` in `show system info`); legacy = routed. Check which one owns the config. `var/log/pan/frr/frr_export.log` exists on every box (even with ARE off); with ARE **on** there is one `ns<N>_frr_export.log` / `ns<N>_frr_reload.log` per logical router (header `#LR:<name> (<n>)`, then FRR-style `YYYY/MM/DD HH:MM:SS ZEBRA: …` lines) plus `are_migration.log`. |
| **Commit / config** | `configd.log`, `show_log_config.txt`, `commit_stats.log` (12.x only) | `cfg-audit.xml,v`, `> show jobs processed` | `commit_stats.log` has per-phase durations (Jobid/Start/Fin blocks); on 10.2–11.2 the durations are in `show jobs processed` and `configd.log` only. |
| **Content / AV updates** | `paninstaller_content.log`, `contentd.log` | `opt/pancfg/mgmt/global/*info.xml` | Correlate the update **time** with the symptom start before blaming it. |
| **Panorama** | `devsrv.log`, `ms.log` | `opt/pancfg/mgmt/tmp/panorama_pushed/` (`lastsp.xml`, `newsp.xml`, `mergesp.xml`, `predefined.xml`, `pushsp.xml`, `sp-push-request.xml`, `tpl-push-request.xml`; `before|after-sp-imported.xml` on 12.x) | `running-config.xml` alone is incomplete on managed devices — use `.merged-running-config.xml`. |

\* alias rule of step 2 applies.

Secondary domains not tabled here — WildFire, URL filtering, QoS, SD-WAN,
DLP, App-ID, DNS/DHCP, licences — follow the same method; their per-problem
log map is in [TSF-GUIDE.md](TSF-GUIDE.md) §4.

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
`panorama_pushed/` — `newsp.xml`/`lastsp.xml`/`mergesp.xml` on 10.2–11.2,
`before|after-sp-imported.xml` as well on 12.x). Structure and grep entry
points: `TSF-GUIDE.md` §5. Two specifics:

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
  `regip/reg_ips.xml`, `*.dat`, `fs_manifest.txt`, `req_stats.log`,
  `tmp/cli/logs/sysd_objects_meta.xml` (the whole sysd tree as XML, 100 MB on
  a chassis; absent on 10.2 — `sdb.txt` is the same data as grep-able dotted keys),
  `last-candidatecfg-audit.xml,v` (RCS history of every *candidate*, tens of
  MB — `cfg-audit.xml,v` is the one with the commits) — are almost never the
  answer; don't burn context reading them.
- **Binary files** (`rule-hit-count.bin`, `wtmp`/`btmp`/`lastlog`,
  `var/log/sa/sa*`, `var/log/pan/sslvpn-access/sslvpn-task.log*.gz` — one
  serialized `GpTaskStat` record per GP request: task id, vsys, source IP,
  HTTP method, user, portal, gateway, auth profile, result) need `grep -a` /
  `strings`, or the matching text export (`sar*`, `rule-hit-count-db.txt`,
  `show_log_globalprotect.txt`).

## Anonymized TSFs

A TSF produced by this repo's anonymizer keeps layout, line counts,
timestamps, counters, interface names and built-ins; identifiers are replaced
consistently (same original → same pseudonym everywhere): `100.64.x.y` was a
private IP, `192.0.2.x`/`198.51.100.x`/`203.0.113.x` public, `hostNNN[.anon.internal]`
a hostname, `userNNN` a user, `ZONE-0012`/`RULE-0045`/`GW-0002`… named objects
(prefix = category), same-length digits starting `9` a serial. Correlation
still works — "peer `203.0.113.7` on `GW-0002`" is the same peer everywhere.
Member names are rewritten with the same mapping — the command dump reads
`tmp/cli/techsupport_host001_<date>.txt`. Binary members that embedded
identifiers are, **by default**, replaced by the one-line
`[tsf-anonymizer] binary payload redacted…`: expect it in `var/log/sa/saNN`
(read the `sarNN` text twins instead), `rule-hit-count.bin` (use
`rule-hit-count-db.txt`), `sslvpn-access/sslvpn-task.log*` (use
`show_log_globalprotect.txt`) and `var/log/wtmp`/`btmp`/`lastlog` — the
admin login history, which has no twin: for "who logged in, when, from
where" use `show_log_system.txt` (`grep -i "logged in\|auth"`) and
`authd.log`. The original is gone from the archive, not hidden. The
`*.mapping.json` sidecar reverses it all and must never travel with the
anonymized archive.

## Before you finish — feed this file

This file is the distillate of every TSF read before yours, and the only
reason the next read is faster. **Analyzing a TSF ends by updating it**, in
the same turn, without being asked:

| what happened during the analysis | what to write here |
| --- | --- |
| a file you needed was not in the map, or lives elsewhere on this PAN-OS version / platform | add the path, with the version or platform that moves it |
| the answer to a symptom took more than one grep | add the working `symptom → file → grep` line to Step 3 |
| a pointer here was wrong: empty grep, renamed command, output that moved | fix it or delete it — a wrong pointer costs more than a missing one |
| a phrasing in a log differs from what Step 2b describes | correct the example line |
| the anonymizer mangled or missed something in this TSF | that belongs in the repo's `.claude/rules/anonymizer-invariants.md` (invariant or known limitation) **and** a test, not here |

Two rules on how to write it:

- **Genericize.** No customer hostname, IP, serial, user, company or case
  number ever enters this file. The pattern is what is worth keeping, the
  value never is. Use the same placeholders the rest of the file uses.
- **Keep `TSF-GUIDE.md` (next to this file) in step.** It is the human-facing
  version of the same knowledge — the file map and per-problem log tables live
  there, the method lives here; when one gains a section the other needs a
  look. `docs/TSF-GUIDE.md` is a pointer page to it, not a copy.

Say in one line what you added, so the person reading your analysis knows the
skill moved.
