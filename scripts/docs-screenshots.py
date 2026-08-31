#!/usr/bin/env python3
"""Generate the documentation screenshots from the synthetic TSF.

Real tech support files are customer material, so the pictures in
``docs/user-guide.md`` come from ``tsf-anonymizer mock-tsf``: this script
starts the real server on a loopback port with a temporary data directory,
drives the web UI with Playwright exactly as a person would (drop two
archives, choose *one mapping per firewall*, start, open the job, the files,
a diff, the run log) and writes one PNG per step to ``docs/screenshots/``.

It doubles as the UI smoke test in CI: a page that fails to render, a job
that does not finish or a control that moved makes it exit non-zero.

    uv sync --group docs && uv run playwright install chromium
    uv run python scripts/docs-screenshots.py            # → docs/screenshots/
    uv run python scripts/docs-screenshots.py --out /tmp/shots --lines 5000 --scheme dark

``TSF_SHOT_BROWSER=/usr/bin/chromium`` uses a system browser instead of the
one Playwright downloads.
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tsf_anonymizer.mock import build_mock_tsf, default_mock_name  # noqa: E402

VIEWPORT = {"width": 1280, "height": 860}


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_http(url: str, timeout: float = 30) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                if r.status == 200:
                    return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError(f"server did not answer on {url}")


def wait_jobs(base: str, timeout: float = 300) -> list[dict]:
    deadline = time.time() + timeout
    while time.time() < deadline:
        with urllib.request.urlopen(f"{base}/api/jobs", timeout=5) as r:
            jobs = json.load(r)
        if jobs and all(j["status"] in ("done", "failed", "interrupted") for j in jobs):
            return jobs
        time.sleep(0.5)
    raise RuntimeError("jobs did not finish in time")


@contextlib.contextmanager
def server(data_dir: Path, port: int):
    env = dict(os.environ, TSF_PASSWORD="", TSF_TLS_CERT="", TSF_TLS_KEY="",
               TSF_WORKERS="2", TSF_ANON_WORKERS="2", TSF_COMPARE_WORKERS="2",
               TSF_DATA_DIR=str(data_dir))
    proc = subprocess.Popen(
        [sys.executable, "-m", "tsf_anonymizer.cli", "serve", "--host", "127.0.0.1",
         "--port", str(port), "--data-dir", str(data_dir)],
        env=env, cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        wait_http(f"http://127.0.0.1:{port}/api/health")
        yield proc
    finally:
        proc.terminate()
        try:
            out = proc.communicate(timeout=10)[0]
        except subprocess.TimeoutExpired:
            proc.kill()
            out = proc.communicate()[0]
        if proc.returncode not in (0, -15):
            print(out, file=sys.stderr)


def shoot(base: str, archives: list[Path], out: Path, scheme: str, browser_path: str | None) -> list[Path]:
    from playwright.sync_api import sync_playwright

    out.mkdir(parents=True, exist_ok=True)
    suffix = "" if scheme == "light" else f"-{scheme}"
    written: list[Path] = []

    def save(name: str, target=None, max_height: int | None = None, **kw) -> None:
        path = out / f"{name}{suffix}.png"
        if target is not None and max_height:
            # A diff of a whole config is thousands of pixels tall: keep the
            # top of the element, at most one screen of it.
            target.scroll_into_view_if_needed()
            box = target.bounding_box()
            page.evaluate(f"window.scrollTo(0, window.scrollY + {box['y']})")
            box = target.bounding_box()
            kw["clip"] = {"x": box["x"], "y": box["y"] + page.evaluate("window.scrollY"),
                          "width": box["width"], "height": min(box["height"], max_height)}
            kw["full_page"] = True
            target = None
        (target or page).screenshot(path=str(path), **kw)
        written.append(path)
        print(f"  {path.relative_to(ROOT) if path.is_relative_to(ROOT) else path}")

    with sync_playwright() as p:
        launch = {"executable_path": browser_path} if browser_path else {}
        browser = p.chromium.launch(**launch)
        ctx = browser.new_context(viewport=VIEWPORT, device_scale_factor=2, color_scheme=scheme)
        page = ctx.new_page()
        errors: list[str] = []
        page.on("pageerror", lambda e: errors.append(str(e)))
        # Element screenshots scroll their target under the sticky header,
        # which then hides the first lines: make it flow for the pictures.
        page.on("load", lambda _: page.add_style_tag(content="header{position:static !important}"))

        # 1. Anonymize tab: two archives dropped, one mapping per firewall.
        page.goto(base + "/#anonymize")
        page.wait_for_selector("#drop-zone")
        page.set_input_files("#tsf-files", [str(a) for a in archives])
        page.wait_for_selector("#file-list li")
        page.check("input[name=seed_policy][value=device]")
        # The diff viewer reads both extracted trees: keep the original for the pictures.
        page.uncheck("input[name=delete_original]")
        page.wait_for_timeout(300)
        save("01-anonymize-batch", page.locator("#form-anonymize"))

        # 2. Start: the UI uploads them one after the other and lands on the jobs list.
        page.click("#form-anonymize button[type=submit]")
        page.wait_for_selector("#tab-jobs.active", timeout=120_000)
        jobs = wait_jobs(base)
        for j in jobs:
            if j["status"] != "done":
                raise RuntimeError(f"job {j['id']} ended {j['status']}: {j.get('error')}")
        page.click("nav .tab[data-tab=jobs]")
        page.wait_for_function(
            "document.querySelectorAll('#jobs-table tbody tr').length >= 2 && "
            "[...document.querySelectorAll('#jobs-table tbody tr')].every(tr => /done/.test(tr.textContent))",
            timeout=30_000)
        save("02-jobs", page.locator("#tab-jobs .card"))

        # 3. The job page: flow, verdict, summary.
        job = sorted(jobs, key=lambda j: j["created_at"])[0]
        page.click(f"#jobs-table tbody tr[data-id='{job['id']}']")
        page.wait_for_selector("#job-summary:not([hidden])")
        page.wait_for_selector("#files-table tbody tr")
        page.wait_for_timeout(300)
        save("03-job-verdict", clip={"x": 0, "y": 0, **VIEWPORT})

        # 4. Every file, with its counts.
        page.select_option("#file-filter", "")
        page.wait_for_function(
            "document.querySelectorAll('#files-table tbody tr').length > 5", timeout=30_000)
        page.locator("#job-files").scroll_into_view_if_needed()
        save("04-job-files", page.locator("#job-files"), max_height=900)

        # 5. A diff, replaced spans highlighted.
        page.click("#files-table tbody tr[data-path$='running-config.xml']")
        page.wait_for_selector("#diff-view:not([hidden]) table.diff")
        page.wait_for_timeout(300)
        save("05-diff-viewer", page.locator("#diff-view"), max_height=720)

        # 6. The run log.
        page.click("#diff-close")
        page.click("#show-log")
        page.wait_for_selector("#log-box:not([hidden]) #log-text")
        page.wait_for_function("document.querySelector('#log-text').textContent.length > 100")
        page.locator("#job-header").scroll_into_view_if_needed()
        save("06-run-log", page.locator("#job-header"))

        # 7. The compare tab.
        page.click("nav .tab[data-tab=compare]")
        page.wait_for_selector("#tab-compare.active")
        save("07-compare", page.locator("#form-compare"))

        browser.close()
        if errors:
            raise RuntimeError("JavaScript errors on the page:\n" + "\n".join(errors))
    return written


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", default=str(ROOT / "docs" / "screenshots"))
    ap.add_argument("--lines", type=int, default=2000, help="log lines per file in the mock TSF")
    ap.add_argument("--scheme", choices=["light", "dark", "both"], default="light")
    ap.add_argument("--keep", action="store_true", help="keep the temporary data directory")
    args = ap.parse_args()

    tmp = Path(tempfile.mkdtemp(prefix="tsf-shots-"))
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    try:
        archives = [
            build_mock_tsf(tmp / default_mock_name(), lines=args.lines, seed=7),
            build_mock_tsf(tmp / default_mock_name("fw-lyon-02"), lines=args.lines // 2, seed=11),
        ]
        schemes = ["light", "dark"] if args.scheme == "both" else [args.scheme]
        for scheme in schemes:
            data_dir = tmp / f"data-{scheme}"
            with server(data_dir, port):
                print(f"{scheme}: server on {base}, data in {data_dir}")
                shoot(base, archives, Path(args.out), scheme, os.getenv("TSF_SHOT_BROWSER"))
    finally:
        if args.keep:
            print(f"kept {tmp}")
        else:
            shutil.rmtree(tmp, ignore_errors=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
