"""FastAPI web UI.

No authentication: this tool is meant to run on the operator's own machine
(the compose file binds 127.0.0.1) and it handles the *un*-anonymized archive.
Do not expose it on a network without putting an authenticating proxy in
front of it.
"""

from __future__ import annotations

import json
import os
from contextlib import asynccontextmanager
import re
import shutil
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from .. import __version__
from ..compare import file_diff
from ..jobs import JobStore

HERE = Path(__file__).parent
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._\-]+")


def _safe_filename(name: str, fallback: str) -> str:
    base = Path(name or "").name
    base = _SAFE_NAME.sub("_", base).strip("._") or fallback
    return base[:200]


def create_app(data_dir: Optional[Path] = None) -> FastAPI:
    data_dir = Path(data_dir or os.getenv("TSF_DATA_DIR", "/data"))
    store = JobStore(data_dir)
    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        store.shutdown()

    app = FastAPI(title="TSF Anonymizer", version=__version__, lifespan=lifespan)
    app.state.store = store
    app.mount("/static", StaticFiles(directory=HERE / "static"), name="static")
    templates = Jinja2Templates(directory=HERE / "templates")

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request):
        return templates.TemplateResponse(request, "index.html", {"version": __version__})

    @app.get("/api/health")
    def health():
        usage = shutil.disk_usage(data_dir)
        return {"ok": True, "version": __version__, "data_dir": str(data_dir),
                "disk_free_bytes": usage.free, "jobs": len(store.list())}

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
                               seed_mapping: Optional[UploadFile] = File(None)):
        job = store.new("anonymize")
        d = store.job_dir(job.id)
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
                             mapping: Optional[UploadFile] = File(None)):
        job = store.new("compare")
        d = store.job_dir(job.id)
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
