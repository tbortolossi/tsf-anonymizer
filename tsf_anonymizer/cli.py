"""Command line entry point: ``tsf-anonymizer anonymize|compare|serve``."""

from __future__ import annotations

import argparse
import json
import logging
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


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn
    from .web.app import create_app
    uvicorn.run(create_app(Path(args.data_dir)), host=args.host, port=args.port)
    return 0


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
    s.set_defaults(fn=cmd_serve)

    args = p.parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    sys.exit(main())
