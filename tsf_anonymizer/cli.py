"""Command line entry point: ``tsf-anonymizer anonymize|compare|serve``."""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path

from .core import anonymize_tsf, default_output_path, mapping_sidecar_path
from .compare import compare_archives


def _progress(phase: str, done: int, total: int, message: str) -> None:
    print(f"  [{phase}] {done}/{total} {message}", file=sys.stderr, end="\r" if done < total else "\n")


def cmd_anonymize(args: argparse.Namespace) -> int:
    inp = Path(args.input)
    out = Path(args.output) if args.output else default_output_path(inp)
    seed = json.loads(Path(args.seed_mapping).read_text()) if args.seed_mapping else None
    report, mapping = anonymize_tsf(inp, None if args.mapping_only else out,
                                    mapping_only=args.mapping_only, seed_mapping=seed,
                                    progress=_progress)
    if args.mapping_only:
        print(json.dumps(mapping, indent=2, ensure_ascii=False))
        return 0
    print(f"{report.files_total} files: {report.modified} modified, {report.unchanged} unchanged, "
          f"{report.binary} binary, {report.errors} errors ({report.duration_s:.1f}s)")
    print("replacements:", json.dumps(report.replacements))
    print("mapping sizes:", json.dumps(report.mapping_sizes))
    print(f"output:  {out}\nmapping: {mapping_sidecar_path(out)}")
    if args.verify:
        rep = compare_archives(inp, out, mapping, progress=_progress)
        _print_compare(rep, args.report)
        if args.delete_original:
            if rep.ok:
                inp.unlink()
                print(f"original deleted: {inp}")
            else:
                print(f"original KEPT (integrity problems): {inp}")
        return 0 if rep.ok else 2
    return 0


def _print_compare(rep, report_path: str | None) -> None:
    s = rep.summary
    print(f"files: {s['files_total']}  identical: {s['identical']}  anonymized: {s['anonymized']}  "
          f"warnings: {s['warnings']}  errors: {s['errors']}")
    print(f"changed lines: {s['changed_lines']}  explained: {s['explained_lines']}  "
          f"unexplained: {s['unexplained_lines']}  leaks: {s['leaks_total']}  "
          f"binary files with identifiers: {s['binary_files_with_identifiers']}")
    if rep.archive:
        print("archive:", json.dumps(rep.archive))
    for f in rep.files:
        if f.status in ("warning", "error"):
            print(f"  {f.status.upper():7s} {f.path}: {'; '.join(f.notes)}")
    if report_path:
        Path(report_path).write_text(json.dumps(rep.to_dict(), indent=2), encoding="utf-8")
        print(f"report: {report_path}")
    print("INTEGRITY OK" if rep.ok else "INTEGRITY PROBLEMS FOUND")


def cmd_compare(args: argparse.Namespace) -> int:
    mapping = json.loads(Path(args.mapping).read_text()) if args.mapping else {}
    rep = compare_archives(Path(args.original), Path(args.anonymized), mapping, progress=_progress)
    _print_compare(rep, args.report)
    return 0 if rep.ok else 2


_LOOPBACK = ("127.0.0.1", "::1", "localhost")


def cmd_serve(args: argparse.Namespace) -> int:
    import os
    import uvicorn
    from .web.app import create_app

    log = logging.getLogger(__name__)
    cert, key = args.ssl_certfile, args.ssl_keyfile
    if bool(cert) != bool(key):
        print("serve: --ssl-certfile and --ssl-keyfile go together", file=sys.stderr)
        return 2
    for label, path in (("certificate", cert), ("key", key)):
        if path and not Path(path).is_file():
            # Refusing to start beats silently downgrading an exposed port to
            # plain HTTP because a file moved.
            print(f"serve: TLS {label} not found: {path}\n"
                  f"       run scripts/make-tls-cert.sh, or set TSF_TLS_CERT= to serve "
                  f"plain HTTP", file=sys.stderr)
            return 2

    app = create_app(Path(args.data_dir))
    exposed = args.host not in _LOOPBACK
    if app.state.auth_enabled:
        log.info("HTTP Basic auth enabled for user %r", os.getenv("TSF_USERNAME", "admin"))
    elif exposed:
        log.warning(
            "serving on %s with no TSF_PASSWORD set: the un-anonymized archives and "
            "the mapping are readable by anyone who can reach this port", args.host)
    if cert:
        log.info("TLS enabled (%s)", cert)
    elif exposed:
        # Basic auth without TLS puts the password on the wire in base64.
        log.warning("serving on %s without TLS: set TSF_TLS_CERT/TSF_TLS_KEY", args.host)

    uvicorn.run(app, host=args.host, port=args.port,
                ssl_certfile=cert or None, ssl_keyfile=key or None)
    return 0


def cmd_healthcheck(args: argparse.Namespace) -> int:
    """Container liveness probe: same client as any other, credentials included."""
    import base64
    import os
    import ssl
    import urllib.request

    scheme = "https" if os.getenv("TSF_TLS_CERT") else "http"
    req = urllib.request.Request(f"{scheme}://127.0.0.1:{args.port}/api/health")
    password = os.getenv("TSF_PASSWORD", "")
    if password:
        # No route is exempt from auth, the probe included.
        raw = f"{os.getenv('TSF_USERNAME', 'admin')}:{password}".encode()
        req.add_header("Authorization", "Basic " + base64.b64encode(raw).decode())
    ctx = None
    if scheme == "https":
        # Liveness, not identity: this connection never leaves the container,
        # and the certificate asserts the LAN name, which 127.0.0.1 is not.
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(req, timeout=args.timeout, context=ctx) as r:
            return 0 if r.status == 200 else 1
    except Exception as exc:  # any failure is an unhealthy container
        print(f"healthcheck: {exc}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    p = argparse.ArgumentParser(prog="tsf-anonymizer")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("anonymize", help="anonymize a TSF archive")
    a.add_argument("input")
    a.add_argument("-o", "--output")
    a.add_argument("--seed-mapping", help="mapping.json from a previous run (same customer)")
    a.add_argument("--mapping-only", action="store_true", help="only print what would be mapped")
    a.add_argument("--verify", action="store_true", help="run the compare mode afterwards")
    a.add_argument("--report", help="write the integrity report JSON here (with --verify)")
    a.add_argument("--delete-original", action="store_true",
                   help="with --verify: delete the input archive when the check is clean")
    a.set_defaults(fn=cmd_anonymize)

    c = sub.add_parser("compare", help="verify an anonymized archive against its original")
    c.add_argument("original")
    c.add_argument("anonymized")
    c.add_argument("--mapping", help="mapping.json sidecar")
    c.add_argument("--report", help="write the integrity report JSON here")
    c.set_defaults(fn=cmd_compare)

    s = sub.add_parser("serve", help="run the web UI")
    s.add_argument("--host", default="0.0.0.0")
    s.add_argument("--port", type=int, default=8090)
    s.add_argument("--data-dir", default="/data")
    s.add_argument("--ssl-certfile", default=os.getenv("TSF_TLS_CERT", ""),
                   help="serve HTTPS with this certificate (env TSF_TLS_CERT)")
    s.add_argument("--ssl-keyfile", default=os.getenv("TSF_TLS_KEY", ""),
                   help="private key for --ssl-certfile (env TSF_TLS_KEY)")
    s.set_defaults(fn=cmd_serve)

    h = sub.add_parser("healthcheck", help="probe a local instance (container HEALTHCHECK)")
    h.add_argument("--port", type=int, default=8090)
    h.add_argument("--timeout", type=float, default=3.0)
    h.set_defaults(fn=cmd_healthcheck)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
