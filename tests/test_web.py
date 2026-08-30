"""Web API tests through the FastAPI TestClient; jobs run on the store's worker thread."""

from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from tsf_anonymizer.web.app import create_app
from conftest import build_tsf, IDENTIFIERS


@pytest.fixture
def client(tmp_path):
    app = create_app(tmp_path / "data")
    with TestClient(app) as c:
        yield c
    app.state.store.shutdown()


def _wait(client, job_id, timeout=30):
    deadline = time.time() + timeout
    while time.time() < deadline:
        job = client.get(f"/api/jobs/{job_id}").json()
        if job["status"] in ("done", "failed", "interrupted"):
            return job
        time.sleep(0.05)
    raise AssertionError("job did not finish")


def test_health_and_index(client):
    assert client.get("/api/health").json()["ok"]
    assert "TSF Anonymizer" in client.get("/").text


def test_anonymize_job_end_to_end(client, tmp_path):
    tsf = build_tsf(tmp_path)
    r = client.post("/api/jobs/anonymize", files={"file": ("in.tgz", tsf.read_bytes())},
                    data={"delete_original": "false"})
    assert r.status_code == 200, r.text
    job = _wait(client, r.json()["id"])
    assert job["status"] == "done", job["error"]
    assert job["compare_summary"]["errors"] == 0
    assert job["archive_check"]["order_preserved"]
    assert set(job["outputs"]) == {"tgz", "mapping", "anonymize_report", "integrity_report"}

    # downloads
    tgz = client.get(f"/api/jobs/{job['id']}/download/tgz")
    assert tgz.status_code == 200 and tgz.content[:2] == b"\x1f\x8b"
    mapping = client.get(f"/api/jobs/{job['id']}/mapping").json()
    assert mapping["named_objects"]
    for ident in IDENTIFIERS:
        assert ident not in json.dumps(client.get(f"/api/jobs/{job['id']}/download/integrity_report").json()["summary"])

    # report filtering + paging
    rep = client.get(f"/api/jobs/{job['id']}/report", params={"status": "warning"}).json()
    assert rep["total"] == 2 and all(f["status"] == "warning" for f in rep["files"])
    rep = client.get(f"/api/jobs/{job['id']}/report", params={"q": "system.log", "limit": 1}).json()
    assert rep["total"] == 2 and len(rep["files"]) == 1

    # diff
    d = client.get(f"/api/jobs/{job['id']}/diff", params={"path": "var/log/pan/system.log"}).json()
    assert d["changed_lines"] > 0
    assert client.get(f"/api/jobs/{job['id']}/diff", params={"path": "../job.json"}).status_code == 400

    # purge trees → diff gone, downloads stay
    assert client.post(f"/api/jobs/{job['id']}/purge-trees").status_code == 200
    assert client.get(f"/api/jobs/{job['id']}/diff", params={"path": "var/log/pan/system.log"}).status_code == 410
    assert client.get(f"/api/jobs/{job['id']}/download/tgz").status_code == 200

    # listing + delete
    assert [j["id"] for j in client.get("/api/jobs").json()] == [job["id"]]
    assert client.delete(f"/api/jobs/{job['id']}").status_code == 200
    assert client.get(f"/api/jobs/{job['id']}").status_code == 404


def test_compare_job(client, tmp_path):
    tsf = build_tsf(tmp_path)
    r = client.post("/api/jobs/anonymize", files={"file": ("in.tgz", tsf.read_bytes())})
    job = _wait(client, r.json()["id"])
    anon_tgz = client.get(f"/api/jobs/{job['id']}/download/tgz").content
    mapping = client.get(f"/api/jobs/{job['id']}/download/mapping").content

    r = client.post("/api/jobs/compare", files={
        "original": ("in.tgz", tsf.read_bytes()),
        "anonymized": ("in_anon.tgz", anon_tgz),
        "mapping": ("m.json", mapping),
    })
    assert r.status_code == 200, r.text
    cmp_job = _wait(client, r.json()["id"])
    assert cmp_job["status"] == "done", cmp_job["error"]
    assert cmp_job["compare_summary"]["ok"] and cmp_job["compare_summary"]["unexplained_lines"] == 0
    assert client.get(f"/api/jobs/{cmp_job['id']}/mapping").json() == json.loads(mapping)


def test_seed_mapping_is_applied(client, tmp_path):
    tsf = build_tsf(tmp_path)
    r = client.post("/api/jobs/anonymize", files={"file": ("in.tgz", tsf.read_bytes())})
    first = _wait(client, r.json()["id"])
    mapping = client.get(f"/api/jobs/{first['id']}/mapping").content
    r = client.post("/api/jobs/anonymize", files={"file": ("in.tgz", tsf.read_bytes()),
                                                   "seed_mapping": ("m.json", mapping)})
    second = _wait(client, r.json()["id"])
    assert second["seed_mapping"]
    assert client.get(f"/api/jobs/{second['id']}/mapping").json() == json.loads(mapping)


def test_bad_uploads(client):
    assert client.post("/api/jobs/anonymize", files={"file": ("e.tgz", b"")}).status_code == 400
    r = client.post("/api/jobs/anonymize", files={"file": ("e.tgz", b"xx"), "seed_mapping": ("m.json", b"{")})
    assert r.status_code == 400
    assert client.get("/api/jobs").json() == []


def test_corrupt_archive_fails_cleanly(client):
    r = client.post("/api/jobs/anonymize", files={"file": ("bad.tgz", b"not a tar at all")})
    job = _wait(client, r.json()["id"])
    assert job["status"] == "failed" and job["error"]


def test_interrupted_job_is_marked_on_restart(tmp_path):
    from tsf_anonymizer.jobs import JobStore
    store = JobStore(tmp_path / "data")
    job = store.new("anonymize")
    job.status = "running"; store._save(job)
    store.shutdown()
    store2 = JobStore(tmp_path / "data")
    assert store2.get(job.id).status == "interrupted"
    store2.shutdown()


def test_delete_original_after_clean_verification(client, tmp_path):
    tsf = build_tsf(tmp_path)
    r = client.post("/api/jobs/anonymize", files={"file": ("in.tgz", tsf.read_bytes())},
                    data={"delete_original": "true"})
    job = _wait(client, r.json()["id"])
    assert job["status"] == "done" and job["original_deleted"] and not job["trees_kept"]
    d = client.app.state.store.job_dir(job["id"])
    assert not (d / "input" / "in.tgz").exists() and not (d / "work").exists()
    assert (d / "output" / "in_anon.tgz").exists()
    assert client.get(f"/api/jobs/{job['id']}/download/tgz").status_code == 200
    assert client.get(f"/api/jobs/{job['id']}/diff", params={"path": "x"}).status_code == 410


def test_original_kept_when_verification_has_problems(client, tmp_path, monkeypatch):
    from tsf_anonymizer import jobs as jobs_mod
    real = jobs_mod.compare_trees

    def broken(*a, **kw):
        rep = real(*a, **kw)
        rep.files[0].status = "error"
        rep.summary = jobs_mod.summarize(rep.files) if hasattr(jobs_mod, "summarize") else rep.summary
        rep.summary["errors"] = 1
        return rep
    monkeypatch.setattr(jobs_mod, "compare_trees", broken)
    tsf = build_tsf(tmp_path)
    r = client.post("/api/jobs/anonymize", files={"file": ("in.tgz", tsf.read_bytes())},
                    data={"delete_original": "true"})
    job = _wait(client, r.json()["id"])
    assert job["status"] == "done" and not job["original_deleted"] and job["original_kept_reason"]
    d = client.app.state.store.job_dir(job["id"])
    assert (d / "input" / "in.tgz").exists()
    # manual deletion after review
    assert client.post(f"/api/jobs/{job['id']}/delete-original").status_code == 200
    assert not (d / "input" / "in.tgz").exists()
    assert client.get(f"/api/jobs/{job['id']}").json()["original_deleted"]


def test_delete_original_defaults(client, tmp_path):
    tsf = build_tsf(tmp_path)
    r = client.post("/api/jobs/anonymize", files={"file": ("in.tgz", tsf.read_bytes())})
    assert r.json()["delete_original"] is True
    _wait(client, r.json()["id"])
    r = client.post("/api/jobs/anonymize", files={"file": ("in.tgz", tsf.read_bytes())},
                    data={"delete_original": "false"})
    job = _wait(client, r.json()["id"])
    assert job["delete_original"] is False and not job["original_deleted"] and job["trees_kept"]
