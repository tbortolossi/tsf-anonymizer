"""Web API tests through the FastAPI TestClient; jobs run on the store's worker thread."""

from __future__ import annotations

import base64
import io
import json
import tarfile
import time

import pytest
from conftest import CONFIG_XML, IDENTIFIERS, LOG_SAMPLE, build_tsf
from fastapi.testclient import TestClient

from tsf_anonymizer.jobs import JobStore
from tsf_anonymizer.web.app import create_app


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
    assert set(job["outputs"]) == {"tgz", "mapping", "anonymize_report", "integrity_report", "log"}

    # downloads
    tgz = client.get(f"/api/jobs/{job['id']}/download/tgz")
    assert tgz.status_code == 200 and tgz.content[:2] == b"\x1f\x8b"
    mapping = client.get(f"/api/jobs/{job['id']}/mapping").json()
    assert mapping["named_objects"]
    for ident in IDENTIFIERS:
        assert ident not in json.dumps(client.get(f"/api/jobs/{job['id']}/download/integrity_report").json()["summary"])

    # redaction is the default: the two binaries that embed identifiers ship
    # as markers (anonymized, not warnings), and the check says so
    assert job["compare_summary"]["binary_redacted"] == 2
    rep = client.get(f"/api/jobs/{job['id']}/report", params={"status": "warning"}).json()
    assert rep["total"] == 0
    rep = client.get(f"/api/jobs/{job['id']}/report", params={"q": "rule-hit-count.bin"}).json()
    assert rep["files"] and all(f["redacted"] for f in rep["files"])
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


def test_archives_filed_under_the_same_firewall_share_a_mapping(client, tmp_path):
    """The device name is the chain: no `seed_from_job`, only a group.

    This is what makes a TSF uploaded next month continue its firewall's
    mapping instead of restarting from a fresh one.
    """
    first = _run(client, build_tsf(tmp_path), group="fw-a")
    same_device = _run(client, _variant_tsf(tmp_path / "second.tgz"), group="fw-a")

    assert same_device["seed_from"] == first["id"]
    assert same_device["seed_source"].startswith(f"job {first['id']}")
    assert _anonymized_log(client, same_device["id"]) == _anonymized_log(client, first["id"])


def test_two_firewalls_dropped_together_get_a_mapping_each(client, tmp_path):
    """One batch, two devices: the batch does not link them, the group does."""
    first = _run(client, build_tsf(tmp_path), batch="b3", group="fw-a")
    other = _run(client, _variant_tsf(tmp_path / "other.tgz"), batch="b3", group="fw-b")

    assert other["seed_from"] is None and other["seed_source"] == ""
    assert _anonymized_log(client, other["id"]) != _anonymized_log(client, first["id"])

    # …and the second archive of the first firewall still continues its own
    # chain, over the other device's job that was queued in between.
    third = _run(client, _variant_tsf(tmp_path / "again.tgz"), batch="b3", group="fw-a")
    assert third["seed_from"] == first["id"]
    assert _anonymized_log(client, third["id"]) == _anonymized_log(client, first["id"])


def test_a_group_chains_past_the_job_that_failed(client, tmp_path):
    """The newest job of a group is the head even when it produced nothing."""
    store = client.app.state.store
    good = _run(client, build_tsf(tmp_path), group="fw-c")
    failed = store.new("anonymize")
    failed.status, failed.group, failed.seed_from = "failed", "fw-c", good["id"]
    store._save(failed)

    after = _run(client, _variant_tsf(tmp_path / "after-failure.tgz"), group="fw-c")
    assert after["seed_from"] == failed.id                        # newest of the group…
    assert after["seed_source"].startswith(f"job {good['id']}")   # …resolved back to a mapping
    assert _anonymized_log(client, after["id"]) == _anonymized_log(client, good["id"])


def test_a_seeded_job_waits_for_its_ancestor_even_when_a_worker_is_free(tmp_path):
    """Several archives run at once; a chained one must not start early.

    The check walks the *whole* chain: a parent that failed fast is settled,
    but the grandparent it would seed from may still be running.
    """
    store = JobStore(tmp_path / "data", workers=4)
    try:
        first = store.new("anonymize")
        first.status = "running"
        second = store.new("anonymize")
        second.seed_from = first.id
        third = store.new("anonymize")
        third.seed_from, third.status = second.id, "queued"
        second.status = "failed"          # settled, but its own ancestor is not

        assert store._chain_clear(second) is False
        assert store._chain_clear(third) is False
        # An archive of another firewall is not held back by any of it.
        assert store._chain_clear(store.new("anonymize")) is True

        first.status = "done"
        assert store._chain_clear(second) is True and store._chain_clear(third) is True
    finally:
        store.shutdown()


def test_a_lone_archive_gets_the_whole_machine(tmp_path, monkeypatch):
    """The per-job process count is a floor, not a ceiling.

    `TSF_WORKERS` x per-job processes is the machine when every archive slot
    is busy; when fewer archives can run, the phase takes the idle share
    instead of leaving three quarters of the cores unused.
    """
    monkeypatch.setattr("tsf_anonymizer.jobs.os.cpu_count", lambda: 16)
    store = JobStore(tmp_path / "data", workers=4)
    try:
        assert store.anon_workers == 4 and store.compare_workers == 4
        # Nothing running at all: the whole machine.
        assert store._phase_workers(store.anon_workers) == 16
        # One job running, three others queued and free to start: the share.
        running = store.new("anonymize")
        running.status = "running"
        store._running.add(running.id)
        for _ in range(3):
            j = store.new("anonymize")
            j.status = "queued"
            store._pending.append(j)
        assert store._phase_workers(store.anon_workers) == 4
        # A chain is sequential: its queued jobs cannot run, so they do not
        # take a share of the CPU from the one that can.
        for j in store._pending:
            j.seed_from = running.id
        assert store._phase_workers(store.anon_workers) == 16
    finally:
        store.shutdown()


def test_a_pinned_process_count_is_never_raised(tmp_path, monkeypatch):
    """An explicit count is an operator pinning the load — honour it."""
    monkeypatch.setattr("tsf_anonymizer.jobs.os.cpu_count", lambda: 16)
    store = JobStore(tmp_path / "data", workers=4, anon_workers=2)
    try:
        assert store._phase_workers(store.anon_workers) == 2
    finally:
        store.shutdown()
    monkeypatch.setenv("TSF_COMPARE_WORKERS", "3")
    store = JobStore(tmp_path / "data" / "env", workers=4)
    try:
        assert store.compare_workers == 3
        assert store._phase_workers(store.compare_workers) == 3
    finally:
        store.shutdown()


def test_a_job_can_be_run_again_from_the_upload_on_disk(client, tmp_path):
    """A restart in the middle of a batch must not cost the uploads."""
    job = _run(client, build_tsf(tmp_path), delete_original="false")
    store = client.app.state.store
    interrupted = store.get(job["id"])
    interrupted.status, interrupted.error = "interrupted", "the service restarted"
    store._save(interrupted)

    r = client.post(f"/api/jobs/{job['id']}/requeue")
    assert r.status_code == 200 and r.json()["status"] == "queued"
    again = _wait(client, job["id"])
    assert again["status"] == "done" and again["error"] is None
    assert again["outputs"]["tgz"] and again["compare_summary"]["errors"] == 0

    # A job whose upload is gone cannot be requeued, and says so.
    store.delete_original(store.get(job["id"]))
    store.get(job["id"]).status = "failed"
    assert client.post(f"/api/jobs/{job['id']}/requeue").status_code == 409


def test_jobs_running_at_the_same_time_keep_separate_logs(client, tmp_path):
    """Each job's log is its own thread's, not everything the process logged."""
    a = client.post("/api/jobs/anonymize", data={"delete_original": "false"},
                    files={"file": ("a.tgz", build_tsf(tmp_path, "a.tgz").read_bytes())}).json()
    b = client.post("/api/jobs/anonymize", data={"delete_original": "false"},
                    files={"file": ("b.tgz", build_tsf(tmp_path / "second", "b.tgz").read_bytes())}).json()
    _wait(client, a["id"]), _wait(client, b["id"])

    log_a = "\n".join(client.get(f"/api/jobs/{a['id']}/log").json()["lines"])
    log_b = "\n".join(client.get(f"/api/jobs/{b['id']}/log").json()["lines"])
    assert a["id"] in log_a and b["id"] not in log_a
    assert b["id"] in log_b and a["id"] not in log_b


def test_a_failed_job_keeps_a_log_with_the_traceback(client):
    """The reason a job died has to survive the container that ran it."""
    r = client.post("/api/jobs/anonymize", files={"file": ("bad.tgz", b"not a tar at all")})
    job = _wait(client, r.json()["id"])
    assert job["status"] == "failed"
    assert "Traceback" in job["error_detail"]

    log = client.get(f"/api/jobs/{job['id']}/log").json()
    text = "\n".join(log["lines"])
    assert "Traceback" in text and f"job {job['id']} failed" in text
    assert not log["truncated"] and log["total"] == len(log["lines"])
    # …and as a file, for a bug report.
    dl = client.get(f"/api/jobs/{job['id']}/download/log")
    assert dl.status_code == 200 and "Traceback" in dl.text


def test_the_log_of_a_clean_run_is_kept_too(client, tmp_path):
    tsf = build_tsf(tmp_path)
    r = client.post("/api/jobs/anonymize", files={"file": ("in.tgz", tsf.read_bytes())},
                    data={"delete_original": "false"})
    job = _wait(client, r.json()["id"])
    assert job["status"] == "done" and job["error_detail"] is None
    log = client.get(f"/api/jobs/{job['id']}/log?tail=1").json()
    assert log["truncated"] and len(log["lines"]) == 1
    assert log["total"] > 1


def test_no_log_for_a_job_that_never_ran(tmp_path):
    from fastapi.testclient import TestClient

    from tsf_anonymizer.jobs import JobStore
    from tsf_anonymizer.web.app import create_app
    store = JobStore(tmp_path / "data")
    job = store.new("anonymize")
    with TestClient(create_app(tmp_path / "data", password="")) as c:
        assert c.get(f"/api/jobs/{job.id}/log").status_code == 404


def test_concurrent_saves_of_one_job_never_race_on_the_temp_file(tmp_path):
    # The worker persists a transition while a request (re-run, cancel) saves
    # the same job: with one shared job.json.tmp the second replace() found
    # nothing to rename — FileNotFoundError, seen as a flaky CI failure.
    from concurrent.futures import ThreadPoolExecutor

    from tsf_anonymizer.jobs import JobStore
    store = JobStore(tmp_path / "data")
    job = store.new("anonymize")

    def hammer(n):
        for _ in range(300):
            job.progress_done = n
            store._save(job)

    with ThreadPoolExecutor(4) as pool:
        list(pool.map(hammer, range(4)))   # re-raises the first exception, if any
    saved = json.loads((store.job_dir(job.id) / "job.json").read_text(encoding="utf-8"))
    assert saved["id"] == job.id
    store.shutdown()
