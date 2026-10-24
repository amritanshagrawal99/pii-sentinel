"""`pii-sentinel scan --url duckdb:///db.duckdb [--table t | --all] [--policies snowflake|databricks]`"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import __version__
from .detectors import HIGH, LOW, MEDIUM
from .masks import databricks_masks, snowflake_policies
from .scanner import list_tables, scan_table

_RANK = {LOW: 0, MEDIUM: 1, HIGH: 2}


def _connect(url: str):
    scheme, _, path = url.partition(":///")
    if scheme == "duckdb":
        import duckdb
        return duckdb.connect(path, read_only=True)
    if scheme == "sqlite":
        import sqlite3
        return sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    raise SystemExit(f"unsupported URL {url!r}: use duckdb:///path or sqlite:///path, or call scan_table() with any DB-API connection")


def to_markdown(findings) -> str:
    lines = [f"# PII scan: {len(findings)} column(s) flagged", ""]
    if not findings:
        return "\n".join(lines + ["No personal data detected."]) + "\n"
    lines += ["| Table | Column | Type | Sensitivity | Confidence | Evidence | Masked sample |", "|---|---|---|---|---|---|---|"]
    for f in sorted(findings, key=lambda f: (-_RANK[f.sensitivity], f.table, f.location)):
        lines.append(f"| `{f.table}` | `{f.location}` | {f.label} | {f.sensitivity} | {f.confidence:.0%} | {f.evidence} "
                     f"({f.match_rate:.0%} of {f.sampled}) | {', '.join(f'`{e}`' for e in f.examples)} |")
    return "\n".join(lines) + "\n"


def cmd_scan(a: argparse.Namespace) -> int:
    conn = _connect(a.url)
    sqlite = a.url.startswith("sqlite")
    tables = a.table
    if a.all:
        tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()] if sqlite \
            else list_tables(conn)
    if not tables:
        raise SystemExit("give --table (repeatable) or --all")
    findings = [f for t in tables for f in scan_table(conn, t, sample=a.sample)]
    report = json.dumps([asdict(f) for f in findings], indent=2) if a.format == "json" else to_markdown(findings)
    sys.stdout.buffer.write(report.encode("utf-8"))
    if a.policies:
        sql = snowflake_policies(findings) if a.policies == "snowflake" else databricks_masks(findings)
        if a.output:
            Path(a.output).write_text(sql, encoding="utf-8")
            print(f"\n{a.policies} policies written to {a.output}")
        else:
            sys.stdout.write("\n" + sql)
    if a.fail_on and any(_RANK[f.sensitivity] >= _RANK[a.fail_on] for f in findings):
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pii-sentinel", description="Find personal data in tables and generate masking policies.")
    p.add_argument("--version", action="version", version=f"pii-sentinel {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--url", required=True, help="duckdb:///path or sqlite:///path (opened read-only)")
    s.add_argument("--table", action="append", help="table to scan (repeatable)")
    s.add_argument("--all", action="store_true", help="scan every table")
    s.add_argument("--sample", type=int, default=1000, help="non-null values sampled per column")
    s.add_argument("--format", choices=["markdown", "json"], default="markdown")
    s.add_argument("--policies", choices=["snowflake", "databricks"], help="also generate masking SQL")
    s.add_argument("-o", "--output", help="file for the generated policy SQL")
    s.add_argument("--fail-on", choices=[LOW, MEDIUM, HIGH], help="exit 1 if a column at or above this sensitivity is found (CI gate)")
    s.set_defaults(func=cmd_scan)
    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    sys.exit(main())
