"""
Post-run verification.

The whole point of the engine is that no valid query is silently skipped, so
after every run we prove it: for each query in the catalog, confirm every slice
reached a successful terminal state. A query PASSES only when all its slices are
`done` (or were `subdivided` into children that are all done) and none are
`failed`, `permanent`, `pending`, or `in_flight`. The run PASSES only when every
query passes.

This is what gets presented to the analyst after each execution.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List

from .catalog import Catalog
from .ledger import (Ledger, STATE_DONE, STATE_FAILED, STATE_IN_FLIGHT,
                     STATE_PENDING, STATE_PERMANENT, STATE_SUBDIVIDED)


@dataclass
class QueryVerification:
    query_id: str
    title: str
    slices_total: int
    done: int
    failed: int
    permanent: int
    pending: int
    in_flight: int
    subdivided: int
    result_rows: int
    status: str            # "pass" | "failed" | "incomplete"
    warnings: List[str] = field(default_factory=list)


@dataclass
class RunVerification:
    run_id: str
    generated_at: float
    passed: bool
    total_queries: int
    passed_queries: int
    totals_by_state: Dict[str, int]
    queries: List[QueryVerification]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


def verify_run(ledger: Ledger, run_id: str, catalog: Catalog,
               result_rows: Dict[str, int] | None = None) -> RunVerification:
    result_rows = result_rows or {}
    qvs: List[QueryVerification] = []
    totals: Dict[str, int] = {}
    passed_queries = 0

    for q in catalog.enabled_queries():
        jobs = ledger.jobs_for_query(run_id, q.id)
        counts = {STATE_DONE: 0, STATE_FAILED: 0, STATE_PERMANENT: 0,
                  STATE_PENDING: 0, STATE_IN_FLIGHT: 0, STATE_SUBDIVIDED: 0}
        for j in jobs:
            counts[j.state] = counts.get(j.state, 0) + 1
            totals[j.state] = totals.get(j.state, 0) + 1

        bad = counts[STATE_FAILED] + counts[STATE_PERMANENT]
        outstanding = counts[STATE_PENDING] + counts[STATE_IN_FLIGHT]
        if bad > 0:
            status = "failed"
        elif outstanding > 0:
            status = "incomplete"
        else:
            status = "pass"
        if status == "pass":
            passed_queries += 1

        warns: List[str] = []
        if q.merge.distinct_cols:
            warns.append("contains estimate_distinct columns; merged distinct "
                         "counts are approximate across slices")

        qvs.append(QueryVerification(
            query_id=q.id, title=q.title, slices_total=len(jobs),
            done=counts[STATE_DONE], failed=counts[STATE_FAILED],
            permanent=counts[STATE_PERMANENT], pending=counts[STATE_PENDING],
            in_flight=counts[STATE_IN_FLIGHT], subdivided=counts[STATE_SUBDIVIDED],
            result_rows=int(result_rows.get(q.id, 0)), status=status, warnings=warns))

    passed = all(qv.status == "pass" for qv in qvs) and len(qvs) > 0
    return RunVerification(
        run_id=run_id, generated_at=time.time(), passed=passed,
        total_queries=len(qvs), passed_queries=passed_queries,
        totals_by_state=totals, queries=qvs)


def format_text(v: RunVerification) -> str:
    lines = []
    verdict = "PASS - all queries completed" if v.passed else "ATTENTION - some queries incomplete"
    lines.append(f"Verification: {verdict}")
    lines.append(f"Queries passed: {v.passed_queries}/{v.total_queries}")
    lines.append(f"Slice states: {v.totals_by_state}")
    lines.append("")
    header = f"{'query':<26} {'status':<11} {'done':>5} {'fail':>5} {'perm':>5} {'pend':>5} {'rows':>7}"
    lines.append(header)
    lines.append("-" * len(header))
    for q in v.queries:
        mark = {"pass": "PASS", "failed": "FAILED", "incomplete": "INCOMPLETE"}[q.status]
        lines.append(f"{q.query_id[:26]:<26} {mark:<11} {q.done:>5} {q.failed:>5} "
                     f"{q.permanent:>5} {q.pending:>5} {q.result_rows:>7}")
    if not v.passed:
        lines.append("")
        lines.append("Re-run with the same --run-id to retry incomplete/failed slices "
                     "(completed slices are skipped).")
    return "\n".join(lines)
