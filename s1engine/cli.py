"""
Command-line entrypoint.

    # Live run over 90 days, 1-day slices, resumable
    python -m s1engine.cli run \
        --case CASE-1234 --entity user@corp.com \
        --catalog catalogs/insider_threat.yaml --lookback 90

    # Offline dry run against the built-in fake backend (no tenant needed)
    python -m s1engine.cli run --case DEMO --entity alice@corp.com \
        --catalog catalogs/insider_threat.yaml --lookback 7 --mock

    # Resume a run that was interrupted (same run id -> same ledger + output dir)
    python -m s1engine.cli run --case CASE-1234 --entity user@corp.com \
        --catalog catalogs/insider_threat.yaml --lookback 90 --run-id CASE-1234-20260716T0900Z

    # Show coverage for an existing run
    python -m s1engine.cli status --run-dir investigations/CASE-1234/CASE-1234-20260716T0900Z
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

from .activity import ActivityLog
from .catalog import load_catalog
from .config import load_config
from .engine import InvestigationEngine, RunParams
from .export import zip_run
from .ledger import Ledger
from .lint import lint_catalog
from .validate import validate_catalog
from .verify import format_text, verify_run


def _make_progress(verbose: bool):
    counters = {"done": 0}

    def prog(e: Dict) -> None:
        ev = e.get("event")
        if ev == "planned":
            print(f"[plan] {e['jobs']} jobs = {e['queries']} queries x {e['slices']} slices")
        elif ev == "resume":
            print(f"[resume] reset {e['reset_in_flight']} stale in-flight jobs to pending")
        elif ev == "slice_done":
            counters["done"] += 1
            if verbose:
                print(f"[ok] {e['query']} {e['slice']} rows={e['rows']} "
                      f"match={e['match_count']} {e['elapsed_s']}s "
                      f"{e['client']} gov={e['gov_limit']}")
            elif counters["done"] % 25 == 0:
                print(f"[..] {counters['done']} slices done")
        elif ev == "slice_cached":
            counters["done"] += 1
            if verbose:
                print(f"[cache] {e['query']} {e['slice']} rows={e['rows']} (served from cache)")
        elif ev == "slice_failed":
            print(f"[FAIL] {e['query']} {e['slice']}: {e['error']}")
        elif ev == "permanent":
            print(f"[PERM] {e['query']} {e['slice']}: {e['error']}")
        elif ev == "subdivided":
            print(f"[split] {e['query']} {e['slice']} -> {e['children']} sub-slices")
        elif ev == "workbook":
            print(f"[xlsx] workbook -> {e['path']}")
        elif ev == "warning":
            print(f"[warn] {e['msg']}")
        elif ev == "finalized":
            print(f"[done] complete={e['complete']} results -> {e['results_dir']}")

    return prog


def _parse_vars(pairs: Optional[List[str]]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for p in pairs or []:
        if "=" not in p:
            raise SystemExit(f"--var must be KEY=VALUE, got: {p}")
        k, v = p.split("=", 1)
        out[k.strip()] = v
    return out


def cmd_run(args: argparse.Namespace) -> int:
    catalog = load_catalog(args.catalog)
    run_id = args.run_id or f"{args.case}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
    run_dir = Path(args.out) / _safe(args.case) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    transport = None
    if args.mock:
        from .testing import FakeTransport
        transport = FakeTransport(throttle_first_n=args.mock_throttle)
        config = load_config(require_credentials=False,
                             console_url="https://mock.local",
                             tokens=[f"mock-tok-{i+1}" for i in range(max(1, args.tokens))],
                             rps=args.rps or 1000.0)
    else:
        overrides = {}
        if args.console_url:
            overrides["console_url"] = args.console_url
        if args.rps:
            overrides["rps"] = args.rps
        config = load_config(**overrides)

    ledger = Ledger(run_dir / "ledger.db")
    activity = ActivityLog(run_dir / "activity.jsonl")
    cache_dir = Path(args.out) / ".slice_cache"
    engine = InvestigationEngine(config, output_root=run_dir, transport=transport,
                                 pool_size=args.pool,
                                 on_progress=_make_progress(args.verbose),
                                 activity=activity,
                                 cache_dir=cache_dir, use_cache=not args.no_cache)
    params = RunParams(
        case_id=args.case, entity=args.entity, lookback_days=args.lookback,
        slice_days=args.slice_days, max_attempts=args.max_attempts,
        subdivide_on_timeout=not args.no_subdivide,
        priority=args.priority, variables=_parse_vars(args.var))

    t0 = time.monotonic()
    engine.plan(run_id, catalog, params, ledger)
    result = engine.run(run_id, ledger, params)
    manifest = engine.finalize(run_id, ledger, catalog, params)
    result_rows = {q["query_id"]: q["result_rows"] for q in manifest["queries"]}
    verification = verify_run(ledger, run_id, catalog, result_rows=result_rows)
    workbook = engine.write_workbook(run_id, manifest, verification.to_dict(), params)
    elapsed = time.monotonic() - t0

    print("\n=== run summary ===")
    print(f"run_id     : {run_id}")
    print(f"output dir : {run_dir}")
    print(f"wall clock : {elapsed:.1f}s")
    print(f"stats      : {json.dumps(result['stats'])}")
    print(f"cache      : {json.dumps(result.get('cache', {}))}")
    if workbook:
        print(f"workbook   : {workbook}")
    print()
    print(format_text(verification))
    activity.log({"event": "verification", "passed": verification.passed,
                  "passed_queries": verification.passed_queries,
                  "total_queries": verification.total_queries})
    ledger.close()
    activity.close()
    return 0 if verification.passed else 2


def cmd_status(args: argparse.Namespace) -> int:
    run_dir = Path(args.run_dir)
    db = run_dir / "ledger.db"
    if not db.is_file():
        raise SystemExit(f"No ledger at {db}")
    ledger = Ledger(db)
    # Discover run_id from the runs table.
    with ledger._lock:  # noqa: SLF001 - read-only introspection for the CLI
        rows = ledger._conn.execute("SELECT run_id, status FROM runs").fetchall()
    for r in rows:
        cov = ledger.coverage(r["run_id"])
        print(f"run {r['run_id']} status={r['status']} complete={cov['complete']}")
        print(f"  states: {json.dumps(cov['totals_by_state'])}")
        for qid, states in sorted(cov["per_query"].items()):
            print(f"  {qid}: {json.dumps(states)}")
    ledger.close()
    return 0


def cmd_export(args: argparse.Namespace) -> int:
    data, fname = zip_run(args.run_dir, kind=args.kind)
    out = Path(args.out) if args.out else Path.cwd() / fname
    out.write_bytes(data)
    print(f"wrote {out}  ({len(data)} bytes, kind={args.kind})")
    return 0


def _pq_file_to_catalog(pq_file: str):
    """Build an in-memory catalog from a plain file of PowerQueries separated by blank
    lines (each block is one query, in order q1, q2, ...)."""
    import re as _re
    from .catalog import Catalog, Query, MergeSpec
    blocks = [b.strip() for b in _re.split(r"\n\s*\n", Path(pq_file).read_text()) if b.strip()]
    if not blocks:
        raise SystemExit(f"no queries found in {pq_file} (separate queries with a blank line)")
    queries = [Query(id=f"q{i + 1}", title=f"query {i + 1}", pq=b, merge=MergeSpec(kind="rows"))
               for i, b in enumerate(blocks)]
    return Catalog(name=Path(pq_file).name, queries=queries)


def cmd_validate(args: argparse.Namespace) -> int:
    """Test harness: lint every query offline, then (unless --lint-only) launch each
    against SDL over a short window with dummy vars to confirm it is accepted. Accepts
    a catalog file, a directory of catalogs, or a plain --pq-file list of queries."""
    catalogs = []   # list of (label, Catalog | Exception)
    if args.pq_file:
        catalogs.append((Path(args.pq_file).name, _pq_file_to_catalog(args.pq_file)))
    else:
        if args.catalog:
            paths = [Path(args.catalog)]
        else:
            d = Path(args.dir)
            paths = sorted(list(d.glob("*.yaml")) + list(d.glob("*.yml")) + list(d.glob("*.json")))
        if not paths:
            raise SystemExit(f"no catalogs found (looked in {args.catalog or args.dir})")
        for p in paths:
            try:
                catalogs.append((p.name, load_catalog(p)))
            except Exception as e:  # noqa: BLE001
                catalogs.append((str(p), e))

    config = None
    transport = None
    if not args.lint_only:
        if args.mock:
            from .testing import FakeTransport
            transport = FakeTransport(fail_query_substr={"BROKEN": "syntax"})
            config = load_config(require_credentials=False, console_url="https://mock.local",
                                 tokens=["mock-tok-1"], rps=1000.0)
        else:
            overrides = {}
            if args.console_url:
                overrides["console_url"] = args.console_url
            if args.rps:
                overrides["rps"] = args.rps
            config = load_config(**overrides)

    lint_total = invalid_total = valid_total = unknown_total = 0
    for label, cat in catalogs:
        if isinstance(cat, Exception):
            print(f"\n== {label} ==\n  PARSE ERROR: {cat}")
            invalid_total += 1
            continue
        print(f"\n== {label}  ({len(cat.enabled_queries())} queries) ==")
        lint = lint_catalog(cat)
        for qid, issues in lint.items():
            for msg in issues:
                print(f"  LINT  {qid}: {msg}")
            lint_total += len(issues)
        if args.lint_only:
            continue
        results = validate_catalog(config, cat, transport=transport,
                                   window_hours=args.window_hours)
        for r in results:
            st = r.get("status")
            if st == "valid":
                valid_total += 1
            elif st == "invalid":
                invalid_total += 1
                print(f"  INVALID {r['query_id']}: {r.get('error', '')}")
            else:
                unknown_total += 1
                print(f"  UNKNOWN {r['query_id']}: {r.get('error', '')}")

    print("\n=== validation summary ===")
    print(f"lint issues : {lint_total}")
    if not args.lint_only:
        print(f"valid       : {valid_total}")
        print(f"invalid     : {invalid_total}")
        print(f"unknown     : {unknown_total} (transient / could not reach SDL)")
    return 0 if (lint_total == 0 and invalid_total == 0) else 1


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in str(name))


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="s1-investigate",
                                description="SentinelOne SDL investigation execution engine")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="plan + execute + finalize an investigation")
    r.add_argument("--case", required=True, help="case id (folder name)")
    r.add_argument("--entity", required=True, help="subject of the investigation (email/user/host/ip)")
    r.add_argument("--catalog", required=True, help="path to the query catalog (.yaml/.json)")
    r.add_argument("--lookback", type=int, default=90, help="lookback window in days (default 90)")
    r.add_argument("--slice-days", type=int, default=1, help="days per slice (default 1)")
    r.add_argument("--out", default="investigations", help="base output directory")
    r.add_argument("--run-id", default=None, help="reuse an existing run id to resume")
    r.add_argument("--pool", type=int, default=None, help="worker pool size (default tokens*3)")
    r.add_argument("--rps", type=float, default=None, help="per-token rate (default 2.5)")
    r.add_argument("--tokens", type=int, default=2, help="number of mock tokens (--mock only)")
    r.add_argument("--console-url", default=None, help="override S1_CONSOLE_URL")
    r.add_argument("--max-attempts", type=int, default=4, help="transient retries per slice")
    r.add_argument("--no-subdivide", action="store_true", help="disable adaptive sub-slicing")
    r.add_argument("--no-cache", action="store_true", help="disable the content-addressed slice cache")
    r.add_argument("--priority", default="LOW", choices=["LOW", "HIGH"])
    r.add_argument("--var", action="append", help="extra template var KEY=VALUE (repeatable)")
    r.add_argument("--mock", action="store_true", help="run offline against the fake backend")
    r.add_argument("--mock-throttle", type=int, default=0, help="inject N throttles (--mock)")
    r.add_argument("-v", "--verbose", action="store_true", help="per-slice progress")
    r.set_defaults(func=cmd_run)

    s = sub.add_parser("status", help="show coverage for an existing run")
    s.add_argument("--run-dir", required=True, help="path to a run directory")
    s.set_defaults(func=cmd_status)

    e = sub.add_parser("export", help="zip a run's outputs (logs/results/all)")
    e.add_argument("--run-dir", required=True, help="path to a run directory")
    e.add_argument("--kind", default="results", choices=["logs", "results", "all"])
    e.add_argument("--out", default=None, help="output .zip path (default: cwd)")
    e.set_defaults(func=cmd_export)

    v = sub.add_parser("validate", help="test harness: lint + validate catalog or raw "
                                        "PowerQueries (with dummy vars) against SDL")
    v.add_argument("--catalog", default=None, help="a single catalog file (default: all in --dir)")
    v.add_argument("--dir", default="catalogs", help="directory of catalogs to validate")
    v.add_argument("--pq-file", default=None,
                   help="a plain file of PowerQueries separated by blank lines (lint a raw list)")
    v.add_argument("--lint-only", action="store_true", help="static checks only, no tenant needed")
    v.add_argument("--mock", action="store_true", help="validate against the offline fake backend")
    v.add_argument("--window-hours", type=int, default=1, help="probe window per query (default 1h)")
    v.add_argument("--console-url", default=None, help="override S1_CONSOLE_URL")
    v.add_argument("--rps", type=float, default=None, help="per-token rate (default 2.5)")
    v.set_defaults(func=cmd_validate)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
