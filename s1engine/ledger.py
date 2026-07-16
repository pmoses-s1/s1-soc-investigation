"""
Durable job ledger (SQLite).

One row per (run, query, slice). Every job has an explicit terminal state, so a
valid query can never be silently skipped: if it is not `done`, it is `pending`,
`failed`, or `permanent`, and you can prove exactly which windows are covered.

The ledger is the resume mechanism. Kill the process mid-run, restart, and the
engine resets any `in_flight` rows back to `pending` and re-runs only what is
outstanding. Content-addressed job ids make planning idempotent: re-planning the
same investigation upserts the same rows instead of duplicating them.

SQLite is used in WAL mode with a process-level write lock so the multithreaded
worker pool can share one connection safely.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


# Job state machine:
#   pending    -> queued, not yet started (or reset after a crash)
#   in_flight  -> a worker currently owns it
#   done       -> completed successfully (result_path written)
#   failed     -> exhausted transient retries this run; retryable on a later run
#   permanent  -> non-retryable (query syntax error / catalog bug); never retried
STATE_PENDING = "pending"
STATE_IN_FLIGHT = "in_flight"
STATE_DONE = "done"
STATE_FAILED = "failed"
STATE_PERMANENT = "permanent"
STATE_SUBDIVIDED = "subdivided"  # parent replaced by child sub-slices

TERMINAL_STATES = (STATE_DONE, STATE_PERMANENT, STATE_SUBDIVIDED)


def job_id(run_id: str, query_id: str, slice_key: str, scope: str) -> str:
    h = hashlib.sha256(f"{run_id}\x1f{query_id}\x1f{slice_key}\x1f{scope}".encode()).hexdigest()
    return h[:24]


@dataclass
class Job:
    job_id: str
    run_id: str
    query_id: str
    slice_key: str
    slice_start: str
    slice_end: str
    scope: str
    pq: str
    state: str = STATE_PENDING
    attempts: int = 0
    lrq_id: Optional[str] = None
    forward_tag: Optional[str] = None
    error: Optional[str] = None
    match_count: Optional[int] = None
    row_count: Optional[int] = None
    result_path: Optional[str] = None
    cpu_ms: Optional[float] = None


_SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id      TEXT PRIMARY KEY,
    case_id     TEXT,
    entity      TEXT,
    catalog     TEXT,
    params_json TEXT,
    status      TEXT,
    created_at  REAL,
    updated_at  REAL
);
CREATE TABLE IF NOT EXISTS jobs (
    job_id       TEXT PRIMARY KEY,
    run_id       TEXT NOT NULL,
    query_id     TEXT NOT NULL,
    slice_key    TEXT NOT NULL,
    slice_start  TEXT NOT NULL,
    slice_end    TEXT NOT NULL,
    scope        TEXT NOT NULL,
    pq           TEXT NOT NULL,
    state        TEXT NOT NULL,
    attempts     INTEGER NOT NULL DEFAULT 0,
    lrq_id       TEXT,
    forward_tag  TEXT,
    error        TEXT,
    match_count  INTEGER,
    row_count    INTEGER,
    result_path  TEXT,
    cpu_ms       REAL,
    created_at   REAL,
    updated_at   REAL
);
CREATE INDEX IF NOT EXISTS idx_jobs_run_state ON jobs(run_id, state);
CREATE INDEX IF NOT EXISTS idx_jobs_run_query ON jobs(run_id, query_id);
"""


class Ledger:
    def __init__(self, db_path: str | Path):
        self.path = str(db_path)
        Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(self.path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        with self._lock:
            self._conn.executescript(_SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ runs
    def record_run(self, run_id: str, case_id: str, entity: str,
                   catalog: str, params: Dict[str, Any]) -> None:
        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT INTO runs(run_id, case_id, entity, catalog, params_json, "
                "status, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?) "
                "ON CONFLICT(run_id) DO UPDATE SET case_id=excluded.case_id, "
                "entity=excluded.entity, catalog=excluded.catalog, "
                "params_json=excluded.params_json, updated_at=excluded.updated_at",
                (run_id, case_id, entity, catalog, json.dumps(params),
                 "planned", now, now),
            )
            self._conn.commit()

    def set_run_status(self, run_id: str, status: str) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE runs SET status=?, updated_at=? WHERE run_id=?",
                (status, time.time(), run_id),
            )
            self._conn.commit()

    # ------------------------------------------------------------------ jobs
    def upsert_job(self, job: Job) -> None:
        """Idempotent insert. Existing terminal/in-progress rows are left as-is
        so re-planning never resets completed work."""
        now = time.time()
        with self._lock:
            cur = self._conn.execute("SELECT state FROM jobs WHERE job_id=?", (job.job_id,))
            row = cur.fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO jobs(job_id, run_id, query_id, slice_key, "
                    "slice_start, slice_end, scope, pq, state, attempts, "
                    "created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                    (job.job_id, job.run_id, job.query_id, job.slice_key,
                     job.slice_start, job.slice_end, job.scope, job.pq,
                     STATE_PENDING, 0, now, now),
                )
            self._conn.commit()

    def reset_stale_in_flight(self, run_id: str) -> int:
        """On resume, any job left in_flight by a dead process goes back to pending."""
        with self._lock:
            cur = self._conn.execute(
                "UPDATE jobs SET state=?, updated_at=? WHERE run_id=? AND state=?",
                (STATE_PENDING, time.time(), run_id, STATE_IN_FLIGHT),
            )
            self._conn.commit()
            return cur.rowcount

    def claimable(self, run_id: str) -> List[Job]:
        """Pending + failed jobs (failed are retried on a later run)."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM jobs WHERE run_id=? AND state IN (?,?) ORDER BY query_id, slice_key",
                (run_id, STATE_PENDING, STATE_FAILED),
            )
            return [self._row_to_job(r) for r in cur.fetchall()]

    def mark_in_flight(self, job_id_: str) -> None:
        self._update(job_id_, state=STATE_IN_FLIGHT, bump_attempt=True)

    def mark_done(self, job_id_: str, *, result_path: str, match_count: int,
                  row_count: int, cpu_ms: float, lrq_id: Optional[str] = None) -> None:
        self._update(job_id_, state=STATE_DONE, result_path=result_path,
                     match_count=match_count, row_count=row_count,
                     cpu_ms=cpu_ms, lrq_id=lrq_id, error=None)

    def mark_failed(self, job_id_: str, error: str) -> None:
        self._update(job_id_, state=STATE_FAILED, error=error)

    def mark_permanent(self, job_id_: str, error: str) -> None:
        self._update(job_id_, state=STATE_PERMANENT, error=error)

    def mark_pending(self, job_id_: str, error: Optional[str] = None) -> None:
        """Requeue within the current run (e.g. after a throttle)."""
        self._update(job_id_, state=STATE_PENDING, error=error)

    def mark_subdivided(self, job_id_: str) -> None:
        self._update(job_id_, state=STATE_SUBDIVIDED)

    def _update(self, job_id_: str, *, state: Optional[str] = None,
                bump_attempt: bool = False, **fields: Any) -> None:
        sets, vals = [], []
        if state is not None:
            sets.append("state=?")
            vals.append(state)
        if bump_attempt:
            sets.append("attempts=attempts+1")
        for k, v in fields.items():
            sets.append(f"{k}=?")
            vals.append(v)
        sets.append("updated_at=?")
        vals.append(time.time())
        vals.append(job_id_)
        with self._lock:
            self._conn.execute(f"UPDATE jobs SET {', '.join(sets)} WHERE job_id=?", vals)
            self._conn.commit()

    def get_job(self, job_id_: str) -> Optional[Job]:
        with self._lock:
            cur = self._conn.execute("SELECT * FROM jobs WHERE job_id=?", (job_id_,))
            row = cur.fetchone()
            return self._row_to_job(row) if row else None

    def jobs_for_query(self, run_id: str, query_id: str, state: Optional[str] = None) -> List[Job]:
        with self._lock:
            if state:
                cur = self._conn.execute(
                    "SELECT * FROM jobs WHERE run_id=? AND query_id=? AND state=? ORDER BY slice_key",
                    (run_id, query_id, state))
            else:
                cur = self._conn.execute(
                    "SELECT * FROM jobs WHERE run_id=? AND query_id=? ORDER BY slice_key",
                    (run_id, query_id))
            return [self._row_to_job(r) for r in cur.fetchall()]

    def all_jobs(self, run_id: str) -> List[Job]:
        with self._lock:
            cur = self._conn.execute(
                "SELECT * FROM jobs WHERE run_id=? ORDER BY query_id, slice_key", (run_id,))
            return [self._row_to_job(r) for r in cur.fetchall()]

    def coverage(self, run_id: str) -> Dict[str, Any]:
        """Per-run and per-query state counts for the manifest / status output."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT query_id, state, COUNT(*) n FROM jobs WHERE run_id=? "
                "GROUP BY query_id, state", (run_id,))
            rows = cur.fetchall()
        per_query: Dict[str, Dict[str, int]] = {}
        totals: Dict[str, int] = {}
        for r in rows:
            per_query.setdefault(r["query_id"], {})[r["state"]] = r["n"]
            totals[r["state"]] = totals.get(r["state"], 0) + r["n"]
        total_jobs = sum(totals.values())
        return {
            "total_jobs": total_jobs,
            "totals_by_state": totals,
            "per_query": per_query,
            "complete": totals.get(STATE_PENDING, 0) == 0
                        and totals.get(STATE_FAILED, 0) == 0
                        and totals.get(STATE_IN_FLIGHT, 0) == 0,
        }

    @staticmethod
    def _row_to_job(r: sqlite3.Row) -> Job:
        return Job(
            job_id=r["job_id"], run_id=r["run_id"], query_id=r["query_id"],
            slice_key=r["slice_key"], slice_start=r["slice_start"],
            slice_end=r["slice_end"], scope=r["scope"], pq=r["pq"],
            state=r["state"], attempts=r["attempts"], lrq_id=r["lrq_id"],
            forward_tag=r["forward_tag"], error=r["error"],
            match_count=r["match_count"], row_count=r["row_count"],
            result_path=r["result_path"], cpu_ms=r["cpu_ms"],
        )
