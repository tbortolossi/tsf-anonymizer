"""FastAPI web UI.

This app handles the *un*-anonymized archive and the mapping that reverses
the pseudonyms, so every route is behind HTTP Basic auth as soon as
``TSF_PASSWORD`` is set -- including ``/api/health`` and ``/static``, since a
health probe leaks the data directory and the job count. Without a password
the app runs open, which is only acceptable on loopback; the compose file
therefore *requires* ``TSF_PASSWORD`` and refuses to start without it.

Basic auth over plain HTTP sends the password in (base64) clear text: it is
meant for a trusted LAN. Anything wider belongs behind a TLS proxy.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
from contextlib import asynccontextmanager
import re
import secrets
import shutil
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import __version__
from ..compare import file_diff
from ..jobs import JobStore, LOG_NAME

HERE = Path(__file__).parent
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._\-]+")


def _safe_filename(name: str, fallback: str) -> str:
    base = Path(name or "").name
    base = _SAFE_NAME.sub("_", base).strip("._") or fallback
    return base[:200]


def _credentials_ok(header: str, username: str, password: str) -> bool:
    """Constant-time check of an ``Authorization: Basic ...`` header."""
    scheme, _, encoded = header.partition(" ")
    if scheme.lower() != "basic":
        return False
    try:
        decoded = base64.b64decode(encoded.strip(), validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    got_user, sep, got_password = decoded.partition(":")
    if not sep:
        return False
    # Both compared, and always both, so the answer does not time-leak which
    # half was wrong.
    ok_user = secrets.compare_digest(got_user, username)
    ok_password = secrets.compare_digest(got_password, password)
    return ok_user and ok_password


def create_app(data_dir: Optional[Path] = None, *,
               username: Optional[str] = None,
               password: Optional[str] = None) -> FastAPI:
    data_dir = Path(data_dir or os.getenv("TSF_DATA_DIR", "/data"))
    username = username if username is not None else os.getenv("TSF_USERNAME", "admin")
    password = password if password is not None else os.getenv("TSF_PASSWORD", "")
    store = JobStore(data_dir)
    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        store.shutdown()

    app = FastAPI(title="TSF Anonymizer", version=__version__, lifespan=lifespan)
    app.state.store = store
    app.state.auth_enabled = bool(password)
    if password:
        @app.middleware("http")
        async def basic_auth(request: Request, call_next):
            if not _credentials_ok(request.headers.get("authorization", ""), username, password):
                # 401 + WWW-Authenticate, so a browser shows its own prompt and
                # curl -u works; no route is exempt, the health probe included.
                return JSONResponse(
                    {"detail": "authentication required"}, status_code=401,
                    headers={"WWW-Authenticate": 'Basic realm="tsf-anonymizer"'})
            return await call_next(request)

    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        return templates.TemplateResponse(request, "index.html", {"version": __version__})

    @app.get("/api/health")
    def health():
        usage = shutil.disk_usage(data_dir)
        return {"ok": True, "version": __version__, "data_dir": str(data_dir),
                "disk_free_bytes": usage.free, "jobs": len(store.list()),
                "workers": store.workers, "compare_workers": store.compare_workers,
                "anon_workers": store.anon_workers}

    # -- jobs ---------------------------------------------------------------

    async def _save_upload(upload: UploadFile, dest: Path) -> int:
        size = 0
        with open(dest, "wb") as f:
            while True:
                chunk = await upload.read(4 * 1024 * 1024)
                if not chunk:
                    break
                f.write(chunk)
                size += len(chunk)
        return size

    @app.post("/api/jobs/anonymize")
    async def create_anonymize(file: UploadFile = File(...),
                               seed_mapping: Optional[UploadFile] = File(None),
                               delete_original: bool = Form(True),
                               redact_binaries: bool = Form(False),
                               batch: Optional[str] = Form(None),
                               group: Optional[str] = Form(None),
                               seed_from_job: Optional[str] = Form(None)):
        """Queue one archive.

        `group` names the device the TSF comes from, and is what decides which
        mapping this job continues: without an explicit `seed_from_job` the
        server chains it to the latest job of the same group. Several firewalls
        uploaded together are several groups, hence several independent
        mappings; the same firewall — in this batch or next month — is one
        group, hence one growing mapping. No group at all means a fresh
        mapping.
        """
        if seed_from_job and store.get(seed_from_job) is None:
            raise HTTPException(404, f"no job {seed_from_job} to seed from")
        job = store.new("anonymize")
        d = store.job_dir(job.id)
        job.delete_original = delete_original
        job.redact_binaries = redact_binaries
        job.batch = _safe_filename(batch, "")[:40] or None if batch else None
        job.group = _safe_filename(group, "")[:40] or None if group else None
        job.seed_from = seed_from_job or None
        if not job.seed_from and job.group:
            previous = store.latest_in_group(job.group, exclude=job.id)
            job.seed_from = previous.id if previous else None
        job.input_name = _safe_filename(file.filename, "input.tgz")
        size = await _save_upload(file, d / "input" / job.input_name)
        if size == 0:
            store.delete(job.id)
            raise HTTPException(400, "empty upload")
        if seed_mapping is not None and seed_mapping.filename:
            raw = await seed_mapping.read()
            try:
                json.loads(raw)
            except ValueError:
                store.delete(job.id)
                raise HTTPException(400, "seed mapping is not valid JSON")
            (d / "input" / "seed.mapping.json").write_bytes(raw)
        store._save(job)
        store.submit(job)
        return job.to_dict()

    @app.post("/api/jobs/compare")
    async def create_compare(original: UploadFile = File(...), anonymized: UploadFile = File(...),
                             mapping: Optional[UploadFile] = File(None),
                             delete_original: bool = Form(False)):
        job = store.new("compare")
        d = store.job_dir(job.id)
        job.delete_original = delete_original
        job.input_name = _safe_filename(original.filename, "original.tgz")
        job.anon_input_name = _safe_filename(anonymized.filename, "anonymized.tgz")
        if job.anon_input_name == job.input_name:
            job.anon_input_name = "anonymized_" + job.anon_input_name
        s1 = await _save_upload(original, d / "input" / job.input_name)
        s2 = await _save_upload(anonymized, d / "input" / job.anon_input_name)
        if not s1 or not s2:
            store.delete(job.id)
            raise HTTPException(400, "empty upload")
        if mapping is not None and mapping.filename:
            raw = await mapping.read()
            try:
                json.loads(raw)
            except ValueError:
                store.delete(job.id)
                raise HTTPException(400, "mapping is not valid JSON")
            (d / "input" / "mapping.json").write_bytes(raw)
        store._save(job)
        store.submit(job)
        return job.to_dict()

    @app.get("/api/jobs")
    def list_jobs():
        return [j.to_dict() for j in store.list()]

    def _job(job_id: str):
        job = store.get(job_id)
        if job is None:
            raise HTTPException(404, "no such job")
        return job

    @app.get("/api/jobs/{job_id}")
    def get_job(job_id: str):
        return _job(job_id).to_dict()

    @app.delete("/api/jobs/{job_id}")
    def delete_job(job_id: str):
        _job(job_id)
        store.delete(job_id)
        return {"deleted": job_id}

    @app.post("/api/jobs/{job_id}/delete-original")
    def delete_original(job_id: str):
        job = _job(job_id)
        if job.status in ("queued", "running"):
            raise HTTPException(409, "job still running")
        store.delete_original(job)
        return {"original_deleted": job_id}

    @app.post("/api/jobs/{job_id}/requeue")
    def requeue(job_id: str):
        """Run a job again from the upload already on disk — what a restart in
        the middle of a batch leaves behind, without re-uploading anything."""
        job = _job(job_id)
        if not store.requeue(job):
            raise HTTPException(409, "cannot requeue: the job is running, or its upload is gone")
        return job.to_dict()

    @app.post("/api/jobs/{job_id}/purge-trees")
    def purge_trees(job_id: str):
        _job(job_id)
        store.purge_trees(job_id)
        return {"purged": job_id}

    @app.get("/api/jobs/{job_id}/report")
    def integrity_report(job_id: str, status: Optional[str] = None, q: Optional[str] = None,
                         offset: int = 0, limit: int = 500):
        job = _job(job_id)
        p = store.job_dir(job.id) / "output" / "integrity-report.json"
        if not p.is_file():
            raise HTTPException(404, "no integrity report yet")
        report = json.loads(p.read_text(encoding="utf-8"))
        files = report["files"]
        if status:
            wanted = set(status.split(","))
            files = [f for f in files if f["status"] in wanted]
        if q:
            ql = q.lower()
            files = [f for f in files if ql in f["path"].lower()]
        total = len(files)
        return {"summary": report["summary"], "archive": report.get("archive", {}),
                "total": total, "offset": offset,
                "files": files[offset: offset + max(1, min(limit, 5000))]}

    @app.get("/api/jobs/{job_id}/log")
    def job_log(job_id: str, tail: int = 300):
        """The run's own log — the traceback of a failure and every file the
        anonymizer had to skip, without shelling into the container."""
        job = _job(job_id)
        p = store.job_dir(job.id) / "output" / LOG_NAME
        if not p.is_file():
            raise HTTPException(404, "no log for this job")
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
        tail = max(1, min(tail, 5000))
        return {"total": len(lines), "truncated": len(lines) > tail,
                "error_detail": job.error_detail, "lines": lines[-tail:]}

    @app.get("/api/jobs/{job_id}/mapping")
    def mapping(job_id: str):
        return store.mapping_for(_job(job_id))

    @app.get("/api/jobs/{job_id}/diff")
    def diff(job_id: str, path: str, context: int = 3, max_hunks: int = 200,
             start_line: int = 1, window: int = 0):
        job = _job(job_id)
        work = store.job_dir(job.id) / "work"
        if not job.trees_kept or not (work / "orig").is_dir():
            raise HTTPException(410, "the extracted trees for this job were purged")
        if ".." in Path(path).parts or path.startswith("/"):
            raise HTTPException(400, "bad path")
        return JSONResponse(file_diff(work / "orig", work / "anon", path, store.mapping_for(job),
                                      context=max(0, min(context, 20)),
                                      max_hunks=max(1, min(max_hunks, 2000)),
                                      start_line=max(1, start_line),
                                      window=max(0, min(window, 2000))))

    @app.get("/api/jobs/{job_id}/download/{what}")
    def download(job_id: str, what: str):
        job = _job(job_id)
        rel = job.outputs.get(what)
        if not rel:
            raise HTTPException(404, f"no output named {what}")
        p = (store.job_dir(job.id) / "output" / rel).resolve()
        if not p.is_file() or store.job_dir(job.id).resolve() not in p.parents:
            raise HTTPException(404, "file not found")
        return FileResponse(p, filename=p.name)

    return app


# uvicorn --factory tsf_anonymizer.web.app:create_app — building the app at
# import time would create $TSF_DATA_DIR just by importing the module.
