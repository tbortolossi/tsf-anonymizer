"""Web API tests through the FastAPI TestClient; jobs run on the store's worker thread."""

from __future__ import annotations

import base64
import io
import json
import tarfile
import time

import pytest
from fastapi.testclient import TestClient

from tsf_anonymizer.web.app import create_app
from conftest import CONFIG_XML, LOG_SAMPLE, build_tsf, IDENTIFIERS


@pytest.fixture
def client(tmp_path):
    # password="" explicitly: the rest of the suite tests the app open, whatever
    # TSF_PASSWORD happens to be exported in the shell running pytest.
    app = create_app(tmp_path / "data", password="")
    with TestClient(app) as c:
        yield c
    app.state.store.shutdown()


@pytest.fixture
def auth_client(tmp_path):
    app = create_app(tmp_path / "data", username="ops", password="s3cret")
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


# -- authentication ---------------------------------------------------------


def test_no_password_configured_leaves_the_app_open(client):
    assert client.get("/api/health").status_code == 200


@pytest.mark.parametrize("path", ["/", "/api/health", "/api/jobs", "/static/app.js"])
def test_every_route_is_behind_basic_auth(auth_client, path):
    # The health probe leaks the data directory and the job count, and /static
    # is served by a mount, not a route: neither may be exempt.
    r = auth_client.get(path)
    assert r.status_code == 401
    assert r.headers["www-authenticate"].startswith("Basic ")


def test_correct_credentials_pass(auth_client):
    assert auth_client.get("/api/health", auth=("ops", "s3cret")).json()["ok"]
    assert "TSF Anonymizer" in auth_client.get("/", auth=("ops", "s3cret")).text


@pytest.mark.parametrize("creds", [("ops", "wrong"), ("admin", "s3cret"), ("", "")])
def test_wrong_credentials_are_rejected(auth_client, creds):
    assert auth_client.get("/api/health", auth=creds).status_code == 401


@pytest.mark.parametrize("header", ["", "Basic", "Bearer s3cret", "Basic !!not-base64!!",
                                    "Basic " + base64.b64encode(b"no-colon").decode()])
def test_malformed_authorization_headers_are_rejected(auth_client, header):
    r = auth_client.get("/api/health", headers={"authorization": header} if header else {})
    assert r.status_code == 401


def test_an_upload_needs_the_password_too(auth_client, tmp_path):
    tsf = build_tsf(tmp_path)
    files = {"file": ("in.tgz", tsf.read_bytes())}
    assert auth_client.post("/api/jobs/anonymize", files=files).status_code == 401
    r = auth_client.post("/api/jobs/anonymize", files=files,
                         data={"delete_original": "false"}, auth=("ops", "s3cret"))
    assert r.status_code == 200


# -- batches ----------------------------------------------------------------


def _variant_tsf(path):
    """The same customer, plus one object declared before the shared ones.

    On a fresh mapping that extra entry takes a counter and shifts everything
    after it, which is what makes the seeded/unseeded difference visible.
    """
    xml = CONFIG_XML.replace(
        '<entry name="SRV-Compta-Paris">',
        '<entry name="AAA-Extra-Net"><ip-netmask>10.9.9.9/32</ip-netmask></entry>\n'
        '          <entry name="SRV-Compta-Paris">', 1)
    members = {"./opt/pancfg/mgmt/saved-configs/running-config.xml": xml.encode(),
               "./var/log/pan/system.log": LOG_SAMPLE.encode("latin-1")}
    with tarfile.open(path, "w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size, info.mtime = len(data), 1700000000
            tar.addfile(info, io.BytesIO(data))
    return path


def _anonymized_log(client, job_id):
    raw = client.get(f"/api/jobs/{job_id}/download/tgz").content
    with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
        member = next(m for m in tar.getmembers() if m.name.endswith("var/log/pan/system.log"))
        return tar.extractfile(member).read()


def _run(client, tsf, **form):
    r = client.post("/api/jobs/anonymize", files={"file": (tsf.name, tsf.read_bytes())},
                    data={"delete_original": "false", **form})
    assert r.status_code == 200, r.text
    job = _wait(client, r.json()["id"])
    assert job["status"] == "done", job["error"]
    return job


def test_a_batch_seeded_from_the_previous_job_shares_its_pseudonyms(client, tmp_path):
    first = _run(client, build_tsf(tmp_path), batch="b1")
    variant = _variant_tsf(tmp_path / "second.tgz")
    seeded = _run(client, variant, batch="b1", seed_from_job=first["id"])
    alone = _run(client, variant)

    # Both archives carry the same log, so with a shared mapping the anonymized
    # log is byte-identical. The unseeded control proves the assertion has
    # teeth: there, the extra object shifts the counters.
    assert _anonymized_log(client, seeded["id"]) == _anonymized_log(client, first["id"])
    assert _anonymized_log(client, alone["id"]) != _anonymized_log(client, first["id"])
    assert seeded["seed_source"].startswith(f"job {first['id']}")
    assert alone["seed_source"] == ""
    assert seeded["batch"] == "b1"


def test_seeding_from_an_unknown_job_is_refused(client, tmp_path):
    tsf = build_tsf(tmp_path)
    r = client.post("/api/jobs/anonymize", files={"file": ("in.tgz", tsf.read_bytes())},
                    data={"seed_from_job": "deadbeef"})
    assert r.status_code == 404


def test_the_chain_walks_back_over_a_job_that_produced_no_mapping(client, tmp_path):
    # A failed job in the middle of a batch must not cost the archives after it
    # their shared pseudonyms, and must not cascade its failure either.
    store = client.app.state.store
    good = _run(client, build_tsf(tmp_path), batch="b2")
    failed = store.new("anonymize")
    failed.status, failed.batch, failed.seed_from = "failed", "b2", good["id"]
    store._save(failed)

    variant = _variant_tsf(tmp_path / "third.tgz")
    third = _run(client, variant, batch="b2", seed_from_job=failed.id)
    assert third["seed_source"].startswith(f"job {good['id']}")
    assert _anonymized_log(client, third["id"]) == _anonymized_log(client, good["id"])


def test_an_uploaded_seed_wins_over_the_chain(client, tmp_path):
    first = _run(client, build_tsf(tmp_path))
    mapping = client.get(f"/api/jobs/{first['id']}/mapping").json()
    variant = _variant_tsf(tmp_path / "fourth.tgz")
    r = client.post("/api/jobs/anonymize",
                    files={"file": (variant.name, variant.read_bytes()),
                           "seed_mapping": ("m.json", json.dumps(mapping).encode())},
                    data={"delete_original": "false", "seed_from_job": first["id"]})
    job = _wait(client, r.json()["id"])
    assert job["seed_source"] == "uploaded mapping"
    assert _anonymized_log(client, job["id"]) == _anonymized_log(client, first["id"])
