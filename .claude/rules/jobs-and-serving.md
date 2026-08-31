---
paths:
  - "tsf_anonymizer/jobs.py"
  - "tsf_anonymizer/cli.py"
  - "tsf_anonymizer/web/**"
  - "tests/test_web.py"
  - "tests/test_cli.py"
  - "Dockerfile"
  - "docker-compose.yml"
  - "scripts/**"
---

# Jobs, web UI, serving — invariants

What must stay true in `jobs.py`, `cli.py`, `web/`, the Dockerfile and
compose: how a job runs, how a batch is ordered, what the server exposes and
refuses. Same rule as for the anonymizer: a lesson from a real run is added
here with its test and a CHANGELOG line, never only fixed.

- **`delete_original` deletes only after a clean integrity report.** Errors
  or archive mismatches keep the original with `original_kept_reason` set;
  a human deletes it via `POST /api/jobs/{id}/delete-original`.
- **The web UI handles the un-anonymized archive and the mapping that
  reverses it**, so HTTP Basic auth (`TSF_PASSWORD`) covers *every* route —
  `/api/health` leaks the data dir and job count, `/static` is a mount, not a
  route; no exemption, the container healthcheck authenticates like any other
  client. `create_app(password="")` runs open, for tests and loopback use;
  compose makes the variable mandatory (`${TSF_PASSWORD:?}`) so nothing is
  ever exposed by omission. Compose binds `127.0.0.1` by default; keep that
  default, `TSF_BIND_ADDR` is the deliberate opt-out.
- **TLS fails closed.** `serve` refuses to start when `TSF_TLS_CERT` points
  at a file that is not there, instead of falling back to plain HTTP — a
  silent downgrade of an exposed port is the failure mode worth designing
  against. Serving policy (TLS, credential warnings) lives in `cmd_serve`,
  not in the Dockerfile `CMD`, so a container and a bare
  `tsf-anonymizer serve` behave identically; the container probe is
  `tsf-anonymizer healthcheck`, a normal client that authenticates and
  speaks TLS when the server does. `scripts/make-tls-cert.sh` keeps the CA
  across runs and reissues only the leaf, so an imported trust anchor
  survives a re-issue.
- **The container runs as the host user** (`user:` in compose) so `./data`
  stays deletable without `sudo`.
- **A batch chains, it does not fan out — and it chains by device, not by
  batch.** Several TSFs dropped together are separate jobs; a shared mapping is
  passed by `seed_from`, which the server resolves at submit time to the
  previous job of the same `group` — the firewall the archive comes from
  (`JobStore.latest_in_group`). Two firewalls in one drop are two groups, hence
  two mappings that never link an identifier across devices; the same group
  name a month later continues *that* firewall's mapping instead of starting
  over. The head of a group is its most recently **created** job, not a
  finished one: inside a batch the next upload arrives while the previous
  archive is still queued, and `_seed_ancestor` walks back at run time over a
  job that produced no mapping — a failure in the middle of a batch must cost
  neither the shared pseudonyms of the archives after it nor their run. An
  uploaded seed wins over the chain, and seeds the first archive of *each*
  group. The UI guesses the device from the filename (PAN-OS names a TSF
  `<date>_<time>_techsupport.tgz`, so what a human added around that is the
  device) and the guess is editable: grouping is the user's call, never the
  filename's.
- **Archives run several at a time; a chain still runs in order.** One TSF is
  two long single-core loops (anonymize, then compare) over a few thousand
  files, so one archive used one core and a batch of eight took a working day.
  `JobStore` runs `TSF_WORKERS` archives at once (cpu/4, capped at 4) and
  `_pump` starts a pending job only when `_chain_clear` says nothing it seeds
  from is still queued or running — the *whole* chain, since a parent that
  failed fast may have a grandparent still running. The wait happens in the
  queue, never inside a worker: a chain of jobs each blocking a worker
  deadlocks a full pool. Because the wait is per chain, a batch of unrelated
  firewalls fans out while a batch of one firewall stays a chain. The job
  threads only *orchestrate*: CPU work on threads serialises on the GIL (a
  4-job batch ran on one core, and one job's regex pass starved another's
  extract into looking hung), so every heavy phase runs in worker processes.
- **Every run keeps its own log.** `_capture_log` tees the package logger into
  `output/job.log` for the duration of one job (they run one at a time, so one
  handler is filtered to that job's own thread, so concurrent jobs do not bleed
  into each other's file), and a crash also stores its traceback in
  `job.error_detail`. The container's stderr is not a log: it is gone the next
  time the container is recreated, and it is the only place that said which
  file and which pattern broke. `core` logs the files it had to skip as
  warnings, and those surface nowhere else — the UI opens the panel by itself
  when a job failed. A failed job also *keeps the phase it died in* so the flow
  marks the step that broke. `Job.phase_durations` records the seconds each
  phase took (also logged at every transition): a slow run says *where* it was
  slow, instead of leaving that to be reconstructed from guesses.
- **A phase that runs for minutes counts.** `extract`, `copy` and `repack` used
  to report `0/1` then `1/1`: on a real TSF the bar sat at 0 % for minutes and
  a slow run could not be told from a hung one. They now report ~100 updates
  whatever the size — `extract` drives `extractall` in slices (which keeps its
  directory-attribute semantics and reads the stream forward-only), `copy`
  counts through `copytree(copy_function=…)`, `repack` through the member loop.
  `Job.updated_at` records when the run last said anything, which is what lets
  the UI say *quiet for 4m* instead of leaving "running" to mean both. The
  jobs list polls every 2 s while anything is queued or running — a batch is
  watched from the list, not from one job's page — and every timer is cleared
  when the view goes away.
- **A capped list says it is capped** (`truncated` in diff hunks, `total` in
  the report endpoint, top-50 leaks per file with a total count).
