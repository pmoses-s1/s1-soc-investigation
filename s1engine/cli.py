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
from .ledger import Ledger
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
        elif ev == "slice_failed":
            print(f"[FAIL] {e['query']} {e['slice']}: {e['error']}")
        elif ev == "permanent":
            print(f"[PERM] {e['query']} {e['slice']}: {e['error']}")
        elif ev == "subdivided":
            print(f"[split] {e['query']} {e['slice']} -> {e['children']} sub-slices")
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
    engine = InvestigationEngine(config, output_root=run_dir, transport=transport,
                                 pool_size=args.pool,
                                 on_progress=_make_progress(args.verbose),
                                 activity=activity)
    params = RunParams(
        case_id=args.case, entity=args.entity, lookback_days=args.lookback,
        slice_days=args.slice_days, max_attempts=args.max_attempts,
        subdivide_on_timeout=not args.no_subdivide,
        priority=args.priority, variables=_parse_vars(args.var))

    t0 = time.monotonic()
    engine.plan(run_id, catalog, params, ledger)
    result = engine.run(run_id, ledger, params)
    manifest = engine.finalize(run_id, ledger, catalog, params)
    elapsed = time.monotonic() - t0

    result_rows = {q["query_id"]: q["result_rows"] for q in manifest["queries"]}
    verification = verify_run(ledger, run_id, catalog, result_rows=result_rows)

    print("\n=== run summary ===")
    print(f"run_id     : {run_id}")
    print(f"output dir : {run_dir}")
    print(f"wall clock : {elapsed:.1f}s")
    print(f"stats      : {json.dumps(result['stats'])}")
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
    r.add_argument("--priority", default="LOW", choices=["LOW", "HIGH"])
    r.add_argument("--var", action="append", help="extra template var KEY=VALUE (repeatable)")
    r.add_argument("--mock", action="store_true", help="run offline against the fake backend")
    r.add_argument("--mock-throttle", type=int, default=0, help="inject N throttles (--mock)")
    r.add_argument("-v", "--verbose", action="store_true", help="per-slice progress")
    r.set_defaults(func=cmd_run)

    s = sub.add_parser("status", help="show coverage for an existing run")
    s.add_argument("--run-dir", required=True, help="path to a run directory")
    s.set_defaults(func=cmd_status)
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
