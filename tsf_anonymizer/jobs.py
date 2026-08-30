"""Background job store for the web UI.

One job = one directory under ``<data_dir>/jobs/<id>/``::

    job.json                 status, phase, progress, timings, errors
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
import shutil
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional

from .core import anonymize_tsf, default_output_path, mapping_sidecar_path
from .compare import compare_archives, compare_trees, compare_members

logger = logging.getLogger(__name__)

STATUSES = ("queued", "running", "done", "failed", "interrupted")


@dataclass
class Job:
    id: str
    kind: str                      # anonymize | compare
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    input_name: str = ""
    anon_input_name: str = ""
    phase: str = ""
    progress_done: int = 0
    progress_total: int = 0
    message: str = ""
    error: Optional[str] = None
    anonymize_summary: Optional[dict] = None
    compare_summary: Optional[dict] = None
    archive_check: Optional[dict] = None
    outputs: dict = field(default_factory=dict)   # name → relative path under output/
    trees_kept: bool = False
    seed_mapping: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


class JobStore:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = Path(data_dir)
        self.jobs_dir = self.data_dir / "jobs"
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self._jobs: dict[str, Job] = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="tsf-job")
        self._load()

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
        tmp = d / "job.json.tmp"
        tmp.write_text(json.dumps(job.to_dict(), indent=2), encoding="utf-8")
        tmp.replace(d / "job.json")

    def job_dir(self, job_id: str) -> Path:
        return self.jobs_dir / job_id

    # -- API ----------------------------------------------------------------

    def list(self) -> list[Job]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)

    def get(self, job_id: str) -> Optional[Job]:
        with self._lock:
            return self._jobs.get(job_id)

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
        self._executor.submit(self._run, job)

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    # -- execution ----------------------------------------------------------

    def _progress_fn(self, job: Job):
        last_save = [0.0]

        def progress(phase: str, done: int, total: int, message: str) -> None:
            job.phase, job.progress_done, job.progress_total, job.message = phase, done, total, message
            now = time.monotonic()
            if now - last_save[0] > 1.0:
                last_save[0] = now
                self._save(job)
        return progress

    def _run(self, job: Job) -> None:
        job.status, job.started_at = "running", time.time()
        self._save(job)
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
            job.status, job.error = "failed", f"{type(e).__name__}: {e}"
        finally:
            job.finished_at = time.time()
            job.phase, job.message = "finished", ""
            self._save(job)

    def _run_anonymize(self, job: Job) -> None:
        d = self.job_dir(job.id)
        input_tgz = d / "input" / job.input_name
        seed = None
        seed_path = d / "input" / "seed.mapping.json"
        if seed_path.is_file():
            seed = json.loads(seed_path.read_text(encoding="utf-8"))
            job.seed_mapping = True
        output_tgz = d / "output" / default_output_path(input_tgz).name
        progress = self._progress_fn(job)

        report, mapping = anonymize_tsf(
            input_tgz, output_tgz, seed_mapping=seed,
            work_root=d / "work", keep_trees=True, progress=progress,
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

        cmp = compare_trees(d / "work" / "orig", d / "work" / "anon", mapping, progress)
        progress("verify", 0, 1, "Checking archive members")
        cmp.archive = compare_members(input_tgz, output_tgz)
        progress("verify", 1, 1, "")
        (d / "output" / "integrity-report.json").write_text(
            json.dumps(cmp.to_dict(), indent=2), encoding="utf-8")
        job.outputs["integrity_report"] = "integrity-report.json"
        job.compare_summary = cmp.summary
        job.archive_check = cmp.archive

    def _run_compare(self, job: Job) -> None:
        d = self.job_dir(job.id)
        orig = d / "input" / job.input_name
        anon = d / "input" / job.anon_input_name
        mapping_path = d / "input" / "mapping.json"
        mapping = json.loads(mapping_path.read_text(encoding="utf-8")) if mapping_path.is_file() else {}
        progress = self._progress_fn(job)
        cmp = compare_archives(orig, anon, mapping, work_root=d / "work",
                               keep_trees=True, progress=progress)
        (d / "output" / "integrity-report.json").write_text(
            json.dumps(cmp.to_dict(), indent=2), encoding="utf-8")
        job.outputs = {"integrity_report": "integrity-report.json"}
        if mapping_path.is_file():
            job.outputs["mapping"] = "../input/mapping.json"
        job.trees_kept = True
        job.compare_summary = cmp.summary
        job.archive_check = cmp.archive

    def mapping_for(self, job: Job) -> dict:
        d = self.job_dir(job.id)
        if job.kind == "anonymize" and job.outputs.get("mapping"):
            p = d / "output" / job.outputs["mapping"]
        else:
            p = d / "input" / "mapping.json"
        return json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {}
