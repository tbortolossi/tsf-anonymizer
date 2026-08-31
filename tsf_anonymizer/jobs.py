"""Background job store for the web UI.

One job = one directory under ``<data_dir>/jobs/<id>/``::

    job.json                 status, phase, progress, timings, errors
    output/job.log           everything the run logged, traceback included
    input/                   uploaded archives (+ mapping for compare jobs)
    work/orig/  work/anon/   extracted trees, kept so the diff viewer can read them
    output/                  <name>_anon.tgz, <name>.mapping.json, integrity-report.json

Jobs run on a single worker thread: the work is CPU-bound and two 300 MB
archives in parallel would only compete for the same core and the same disk.
State is written to ``job.json`` on every transition, so a restart of the
container lists every job that has ever run (a job that was *running* at
restart is marked ``interrupted``).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import threading
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .compare import compare_archives, compare_members, compare_trees
from .core import anonymize_tsf, default_output_path, mapping_sidecar_path

logger = logging.getLogger(__name__)

STATUSES = ("queued", "running", "done", "failed", "interrupted")
LOG_NAME = "job.log"


class _ThreadFilter(logging.Filter):
    """Keep only what one job's own worker thread logged.

    Jobs can run several at a time, each with its own handler on the package
    logger, and a handler sees *every* record. A job runs entirely on one
    worker thread, so the thread id is exactly "this job" — without this filter
    every log would collect every other job's lines.
    """

    def __init__(self, thread_id: int) -> None:
        super().__init__()
        self.thread_id = thread_id

    def filter(self, record: logging.LogRecord) -> bool:
        return record.thread == self.thread_id


# The package level is global, so the last job to finish must not lower it
# under the jobs still running: raise it for the first, restore it for the last.
_LEVEL_LOCK = threading.Lock()
_LEVEL_STATE: dict = {"users": 0, "previous": logging.NOTSET}


@contextmanager
def _capture_log(path: Path):
    """Tee everything this job's thread logs into the job's own directory.

    A traceback that only reached the container's stderr is gone as soon as the
    container is recreated, and it is the one thing that says which file and
    which pattern broke. Warnings matter as much as the crash: `core` logs the
    files it had to skip, and those never surface anywhere else.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    handler.setLevel(logging.INFO)
    handler.addFilter(_ThreadFilter(threading.get_ident()))
    pkg = logging.getLogger(__name__.split(".")[0])
    # Under uvicorn the root logger sits at WARNING, which would drop the INFO
    # trail; NOTSET (0) means "inherit", so it has to be raised, not lowered.
    with _LEVEL_LOCK:
        if _LEVEL_STATE["users"] == 0:
            _LEVEL_STATE["previous"] = pkg.level
            pkg.setLevel(min(pkg.level or logging.INFO, logging.INFO))
        _LEVEL_STATE["users"] += 1
    pkg.addHandler(handler)
    try:
        yield
    finally:
        pkg.removeHandler(handler)
        with _LEVEL_LOCK:
            _LEVEL_STATE["users"] -= 1
            if _LEVEL_STATE["users"] == 0:
                pkg.setLevel(_LEVEL_STATE["previous"])
        handler.close()




@dataclass
class Job:
    id: str
    kind: str                      # anonymize | compare
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    # When the run last said anything. A phase that reports no movement for
    # minutes is the one thing a status of "running" cannot express, and it is
    # exactly what a watcher needs to tell a slow job from a stuck one.
    updated_at: float | None = None
    input_name: str = ""
    anon_input_name: str = ""
    phase: str = ""
    progress_done: int = 0
    progress_total: int = 0
    message: str = ""
    error: str | None = None
    # The one-line reason is what the UI shows; the traceback is what fixes the
    # code, so it is kept with the job instead of only in the container's stderr.
    error_detail: str | None = None
    anonymize_summary: dict | None = None
    compare_summary: dict | None = None
    archive_check: dict | None = None
    outputs: dict = field(default_factory=dict)   # name → relative path under output/
    trees_kept: bool = False
    seed_mapping: bool = False
    # A batch is several TSFs dropped together. `seed_from` chains a job to the
    # previous one of its batch, so the whole batch shares one growing mapping
    # and the same customer keeps the same pseudonyms across archives.
    batch: str | None = None
    # The device the archive comes from. Chaining follows the group, not the
    # batch: several firewalls dropped together are several chains, and a TSF
    # taken next month under the same group name continues its firewall's own
    # mapping instead of starting a new one.
    group: str | None = None
    seed_from: str | None = None
    seed_source: str = ""
    # Delete the un-anonymized upload once the integrity check is clean. When
    # the check finds problems the original is kept so a human can review the
    # diff, and `original_kept_reason` says so.
    delete_original: bool = False
    original_deleted: bool = False
    original_kept_reason: str | None = None
    # Replace binary payloads that embed mapping identifiers with a sentinel
    # instead of shipping them untouched. Deliberate data loss — operator's
    # choice, verified (not trusted) by the compare.
    redact_binaries: bool = False
    # Seconds spent in each phase, recorded as the run leaves it. This is the
    # observability every performance question so far had to reconstruct from
    # guesses — a slow run says *where* it was slow.
    phase_durations: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _worker_counts(workers: int | None, compare_workers: int | None,
                   anon_workers: int | None = None) -> tuple[int, int, int]:
    """How many archives at a time, and how many processes each one's heavy
    passes may use.

    The job threads only orchestrate — Python's GIL means CPU work on threads
    serialises, so every heavy phase (text prescan, rewrite, compare) runs in
    worker *processes*. The product of archive count × per-archive processes
    is what lands on the CPU, hence the division: raising one lowers the other
    unless set explicitly. The anonymize and compare phases of one job never
    overlap, so they share the same per-job process budget by default
    (`TSF_ANON_WORKERS` overrides).
    """
    cpu = os.cpu_count() or 4
    workers = workers if workers is not None else int(os.getenv("TSF_WORKERS") or 0)
    workers = max(1, workers or min(4, max(1, cpu // 4)))
    compare_workers = (compare_workers if compare_workers is not None
                       else int(os.getenv("TSF_COMPARE_WORKERS") or 0))
    compare_workers = max(1, compare_workers or min(4, max(1, cpu // workers)))
    anon_workers = (anon_workers if anon_workers is not None
                    else int(os.getenv("TSF_ANON_WORKERS") or 0))
    anon_workers = max(1, anon_workers or compare_workers)
    return workers, compare_workers, anon_workers


class JobStore:
    def __init__(self, data_dir: Path, workers: int | None = None,
                 compare_workers: int | None = None,
                 anon_workers: int | None = None) -> None:
        self.data_dir = Path(data_dir)
        self.jobs_dir = self.data_dir / "jobs"
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self.workers, self.compare_workers, self.anon_workers = _worker_counts(
            workers, compare_workers, anon_workers)
        self._executor = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="tsf-job")
        # Jobs waiting for a free worker *or* for the job they seed from.
        self._pending: list[Job] = []
        self._running: set[str] = set()
        self._load()
        logger.info("job store: %d worker(s), %d anonymize + %d compare process(es) each",
                    self.workers, self.anon_workers, self.compare_workers)

    # -- persistence --------------------------------------------------------

    def _load(self) -> None:
        for d in sorted(self.jobs_dir.iterdir()):
            f = d / "job.json"
            if not f.is_file():
                continue
            try:
                job = Job(**json.loads(f.read_text(encoding="utf-8")))
            except Exception as e:  # pragma: no cover
                logger.warning("skipping unreadable job %s: %s", d.name, e)
                continue
            if job.status in ("queued", "running"):
                job.status = "interrupted"
                job.error = "the service restarted while this job was running"
                self._save(job)
            self._jobs[job.id] = job

    def _save(self, job: Job) -> None:
        d = self.job_dir(job.id)
        d.mkdir(parents=True, exist_ok=True)
        # One temp file per writer: the worker persisting a transition and a
        # request saving the same job (re-run, cancel) used to share
        # job.json.tmp, and the second replace() found nothing to rename.
        # replace() is atomic, so the last writer wins whole; no lock needed.
        tmp = d / f"job.json.{os.getpid()}.{threading.get_ident()}.tmp"
        tmp.write_text(json.dumps(job.to_dict(), indent=2), encoding="utf-8")
        tmp.replace(d / "job.json")

    def job_dir(self, job_id: str) -> Path:
        return self.jobs_dir / job_id

    # -- API ----------------------------------------------------------------

    def list(self) -> list[Job]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)

    def get(self, job_id: str) -> Job | None:
        with self._lock:
            return self._jobs.get(job_id)

    def latest_in_group(self, group: str, exclude: str | None = None) -> Job | None:
        """Head of a device group's chain: its most recently *created* job.

        Created, not finished: inside one batch the next upload arrives while
        the previous archive is still queued, so waiting for a mapping to exist
        would break the chain exactly when it is needed. Pointing at a job that
        has not run yet — or that ends up failing — costs nothing, because
        `_seed_ancestor` walks the chain back at run time until it finds a
        mapping.
        """
        if not group:
            return None
        with self._lock:
            candidates = [j for j in self._jobs.values()
                          if j.kind == "anonymize" and j.group == group and j.id != exclude]
        return max(candidates, key=lambda j: j.created_at, default=None)

    def new(self, kind: str) -> Job:
        job = Job(id=uuid.uuid4().hex[:12], kind=kind)
        with self._lock:
            self._jobs[job.id] = job
        d = self.job_dir(job.id)
        (d / "input").mkdir(parents=True, exist_ok=True)
        (d / "output").mkdir(parents=True, exist_ok=True)
        (d / "work").mkdir(parents=True, exist_ok=True)
        self._save(job)
        return job

    def delete(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.pop(job_id, None)
        if job is None:
            return False
        shutil.rmtree(self.job_dir(job_id), ignore_errors=True)
        return True

    def purge_trees(self, job_id: str) -> bool:
        job = self.get(job_id)
        if job is None:
            return False
        shutil.rmtree(self.job_dir(job_id) / "work", ignore_errors=True)
        job.trees_kept = False
        self._save(job)
        return True

    def submit(self, job: Job) -> None:
        with self._lock:
            self._pending.append(job)
        self._pump()

    def requeue(self, job: Job) -> bool:
        """Run a finished, failed or interrupted job again.

        The upload is still under `input/`, so a job the service restarted out
        of — or one that died on something since fixed — costs a click, not a
        re-upload of 300 MB.
        """
        if job.status in ("queued", "running"):
            return False
        d = self.job_dir(job.id)
        needed = [job.input_name] + ([job.anon_input_name] if job.kind == "compare" else [])
        if not all(n and (d / "input" / n).is_file() for n in needed):
            return False
        job.status, job.error, job.error_detail = "queued", None, None
        job.phase, job.message = "", ""
        job.progress_done = job.progress_total = 0
        job.started_at = job.finished_at = None
        job.updated_at = time.time()
        job.outputs, job.anonymize_summary = {}, None
        job.compare_summary, job.archive_check = None, None
        job.original_deleted, job.original_kept_reason = False, None
        job.phase_durations = {}
        self._save(job)
        self.submit(job)
        return True

    def _chain_clear(self, job: Job) -> bool:
        """True when nothing this job seeds from is still queued or running.

        The *whole* chain is checked, not just the link: a job whose parent
        failed fast still has to wait for the grandparent, because that is
        where `_seed_ancestor` will end up looking for a mapping.
        """
        seen, prev_id = {job.id}, job.seed_from
        while prev_id and prev_id not in seen:
            seen.add(prev_id)
            prev = self._jobs.get(prev_id)
            if prev is None:
                return True
            if prev.status in ("queued", "running"):
                return False
            prev_id = prev.seed_from
        return True

    def _pump(self) -> None:
        """Start every pending job whose chain is clear, up to the worker count.

        The wait for a seed ancestor happens *here*, in the queue, not inside a
        worker: a chain of jobs each blocking a worker would deadlock a full
        pool. A job that is not ready is skipped and the next group's job runs
        instead — which is the whole point of grouping by firewall.
        """
        while True:
            with self._lock:
                if len(self._running) >= self.workers:
                    return
                ready = next((j for j in self._pending if self._chain_clear(j)), None)
                if ready is None:
                    return
                self._pending.remove(ready)
                self._running.add(ready.id)
            self._executor.submit(self._run_then_pump, ready)

    def _run_then_pump(self, job: Job) -> None:
        try:
            self._run(job)
        finally:
            with self._lock:
                self._running.discard(job.id)
            self._pump()

    def delete_original(self, job: Job, reason: str = "") -> None:
        """Remove every copy of the un-anonymized content: the uploaded
        archive(s) and the extracted trees. The outputs stay."""
        d = self.job_dir(job.id)
        for name in (job.input_name, job.anon_input_name if job.kind == "compare" else ""):
            if name:
                (d / "input" / name).unlink(missing_ok=True)
        shutil.rmtree(d / "work", ignore_errors=True)
        job.trees_kept = False
        job.original_deleted = True
        job.original_kept_reason = None
        self._save(job)

    def _maybe_delete_original(self, job: Job, summary: dict, archive: dict) -> None:
        if not job.delete_original:
            return
        clean = summary.get("errors", 0) == 0 and not archive.get("mismatches")
        if clean:
            self.delete_original(job)
        else:
            job.original_kept_reason = (
                "integrity problems found — the original is kept for review; "
                "delete it manually once you have looked at the report"
            )

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    # -- execution ----------------------------------------------------------

    def _progress_fn(self, job: Job):
        last_save = [0.0]
        current: list = [None, 0.0]  # phase name, monotonic start

        def progress(phase: str, done: int, total: int, message: str) -> None:
            now = time.monotonic()
            if phase != current[0]:
                if current[0] is not None:
                    took = now - current[1]
                    job.phase_durations[current[0]] = round(
                        job.phase_durations.get(current[0], 0.0) + took, 1)
                    logger.info("job %s: phase %s took %.1fs", job.id, current[0], took)
                current[0], current[1] = phase, now
            job.phase, job.progress_done, job.progress_total, job.message = phase, done, total, message
            job.updated_at = time.time()
            if now - last_save[0] > 1.0:
                last_save[0] = now
                self._save(job)
        return progress

    def _run(self, job: Job) -> None:
        job.status = "running"
        job.started_at = job.updated_at = time.time()
        self._save(job)
        with _capture_log(self.job_dir(job.id) / "output" / LOG_NAME):
            logger.info("job %s: %s %s", job.id, job.kind, job.input_name or "?")
            try:
                if job.kind == "anonymize":
                    self._run_anonymize(job)
                elif job.kind == "compare":
                    self._run_compare(job)
                else:
                    raise ValueError(f"unknown job kind {job.kind}")
                job.status = "done"
            except Exception as e:
                logger.exception("job %s failed", job.id)
                # The reason before the verdict: the API serves this object
                # straight from memory, so a reader polling every 50 ms could
                # see status "failed" with error_detail still None.
                job.error = f"{type(e).__name__}: {e}"
                job.error_detail = traceback.format_exc()
                job.status = "failed"
            finally:
                job.finished_at = job.updated_at = time.time()
                # A failure keeps the phase it died in, so the flow in the UI
                # marks the step that broke instead of showing every step up to
                # the verdict as done.
                job.phase = job.phase if job.status == "failed" else "finished"
                job.message = ""
                # Set after the run: _run_anonymize / _run_compare assign
                # `outputs` wholesale, and the log is an output of both.
                job.outputs["log"] = LOG_NAME
                logger.info("job %s %s in %.1fs", job.id, job.status,
                            job.finished_at - (job.started_at or job.finished_at))
                self._save(job)

    def _run_anonymize(self, job: Job) -> None:
        d = self.job_dir(job.id)
        input_tgz = d / "input" / job.input_name
        seed, job.seed_source = None, ""
        seed_path = d / "input" / "seed.mapping.json"
        if seed_path.is_file():
            seed = json.loads(seed_path.read_text(encoding="utf-8"))
            job.seed_source = "uploaded mapping"
        elif job.seed_from:
            prev, seed = self._seed_ancestor(job)
            if prev is not None:
                job.seed_source = f"job {prev.id} ({prev.input_name})"
        job.seed_mapping = bool(seed)
        output_tgz = d / "output" / default_output_path(input_tgz).name
        progress = self._progress_fn(job)

        report, mapping = anonymize_tsf(
            input_tgz, output_tgz, seed_mapping=seed,
            work_root=d / "work", keep_trees=True, progress=progress,
            workers=self.anon_workers, redact_binaries=job.redact_binaries,
        )
        job.anonymize_summary = {k: v for k, v in report.to_dict().items() if k != "files"}
        (d / "output" / "anonymize-report.json").write_text(
            json.dumps(report.to_dict(), indent=2), encoding="utf-8")
        job.outputs = {
            "tgz": output_tgz.name,
            "mapping": mapping_sidecar_path(output_tgz).name,
            "anonymize_report": "anonymize-report.json",
        }
        job.trees_kept = True
        self._save(job)

        cmp = compare_trees(d / "work" / "orig", d / "work" / "anon", mapping, progress,
                            workers=self.compare_workers)
        cmp.archive = compare_members(input_tgz, output_tgz, progress, mapping)
        progress("finished", 1, 1, "")  # closes out the last phase's duration
        (d / "output" / "integrity-report.json").write_text(
            json.dumps(cmp.to_dict(), indent=2), encoding="utf-8")
        job.outputs["integrity_report"] = "integrity-report.json"
        job.compare_summary = cmp.summary
        job.archive_check = cmp.archive
        self._maybe_delete_original(job, cmp.summary, cmp.archive)

    def _seed_ancestor(self, job: Job) -> tuple[Job | None, dict | None]:
        """Nearest ancestor in the batch chain that produced a mapping.

        Walking back matters: a job that failed produced nothing to be
        consistent with, and cascading its failure through the rest of the
        batch would lose the shared pseudonyms for the archives that are fine.
        """
        seen, prev_id = {job.id}, job.seed_from
        while prev_id and prev_id not in seen:
            seen.add(prev_id)
            prev = self.get(prev_id)
            if prev is None:
                return None, None
            mapping = self.mapping_for(prev) if prev.status == "done" else {}
            if mapping:
                return prev, mapping
            prev_id = prev.seed_from
        return None, None

    def _run_compare(self, job: Job) -> None:
        d = self.job_dir(job.id)
        orig = d / "input" / job.input_name
        anon = d / "input" / job.anon_input_name
        mapping_path = d / "input" / "mapping.json"
        mapping = json.loads(mapping_path.read_text(encoding="utf-8")) if mapping_path.is_file() else {}
        progress = self._progress_fn(job)
        cmp = compare_archives(orig, anon, mapping, work_root=d / "work",
                               keep_trees=True, progress=progress,
                               workers=self.compare_workers)
        progress("finished", 1, 1, "")  # closes out the last phase's duration
        (d / "output" / "integrity-report.json").write_text(
            json.dumps(cmp.to_dict(), indent=2), encoding="utf-8")
        job.outputs = {"integrity_report": "integrity-report.json"}
        if mapping_path.is_file():
            job.outputs["mapping"] = "../input/mapping.json"
        job.trees_kept = True
        job.compare_summary = cmp.summary
        job.archive_check = cmp.archive
        self._maybe_delete_original(job, cmp.summary, cmp.archive)

    def mapping_for(self, job: Job) -> dict:
        d = self.job_dir(job.id)
        if job.kind == "anonymize" and job.outputs.get("mapping"):
            p = d / "output" / job.outputs["mapping"]
        else:
            p = d / "input" / "mapping.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}
