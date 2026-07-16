"""
Investigation execution engine.

Ties the pieces together:

  plan()  - expand (catalog x slices) into ledger jobs (idempotent).
  run()   - resume, then drain the pending jobs through a worker pool that
            round-robins across service-user tokens, obeys the per-token rate
            buckets and the AIMD concurrency controller, classifies every
            failure, and writes per-slice results.
  finalize() - merge each query's slice results into one table + a run manifest.

The work queue is dynamic: a throttled job is requeued (not failed), a slow job
that exhausts transient retries is subdivided into sub-slices, and a query
syntax error is marked permanent. Nothing is ever silently dropped; every job
ends in a terminal ledger state you can audit.
"""

from __future__ import annotations

import csv
import json
import queue
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from .activity import ActivityLog
from .cache import SliceCache
from .catalog import Catalog, Query
from .config import EngineConfig
from .ledger import (Job, Ledger, STATE_DONE, STATE_FAILED, STATE_PERMANENT,
                     job_id as make_job_id)
from .lrq_client import (LRQClient, QuerySyntaxError, RateLimitError,
                         ServerError, LRQError, RequestsTransport, Transport)
from .merge import merge_query_results
from .rate_limiter import AIMDController, TokenBucket
from .slicing import Slice, iso_z, slices_for_lookback, subdivide
from .workbook import build_workbook


ProgressFn = Callable[[Dict[str, Any]], None]


@dataclass
class RunParams:
    case_id: str
    entity: str
    lookback_days: int
    slice_days: int = 1
    max_attempts: int = 4
    subdivide_on_timeout: bool = True
    priority: str = "LOW"
    variables: Optional[Dict[str, str]] = None


class InvestigationEngine:
    def __init__(self, config: EngineConfig, output_root: str | Path,
                 *, transport: Optional[Transport] = None,
                 pool_size: Optional[int] = None,
                 on_progress: Optional[ProgressFn] = None,
                 activity: Optional["ActivityLog"] = None,
                 cache_dir: Optional[str | Path] = None,
                 use_cache: bool = True):
        self.config = config
        self.output_root = Path(output_root)
        self.on_progress = on_progress or (lambda e: None)
        self.activity = activity
        # Phase 2: shared content-addressed cache for immutable past-day slices.
        self.cache = SliceCache(cache_dir or (self.output_root / ".slice_cache"),
                                enabled=use_cache)
        self._cutoff_iso: Optional[str] = None

        # One client per token, each with its own rate bucket. A shared transport
        # is used for mock runs; real runs get a pooled RequestsTransport.
        shared_transport = transport
        self.clients: List[LRQClient] = []
        tokens = config.tokens or (["__mock__"] if transport is not None else [])
        for i, tok in enumerate(tokens):
            tp = shared_transport or RequestsTransport(
                verify_tls=config.verify_tls,
                pool_maxsize=max(12, (pool_size or 3)))
            bucket = TokenBucket(rps=config.rps, burst=config.burst)
            self.clients.append(LRQClient(
                config.console_url or "https://mock.local", tok, bucket, tp,
                name=f"tok{i+1}", poll_interval_s=config.poll_interval_s,
                query_timeout_s=config.query_timeout_s))
        if not self.clients:
            raise RuntimeError("No LRQ clients configured (no tokens and no transport).")

        # Start concurrency at ~3 in-flight per token, self-tuning via AIMD.
        initial = pool_size or (len(self.clients) * 3)
        self.governor = AIMDController(initial=initial, minimum=1,
                                       maximum=max(initial, len(self.clients) * 6))
        self._pool_size = max(initial, len(self.clients) * 3)
        self._rr = 0
        self._rr_lock = threading.Lock()

    def _emit(self, event: Dict[str, Any]) -> None:
        """Persist every event to the activity log and forward to the live callback."""
        if self.activity is not None:
            self.activity.log(event)
        self.on_progress(event)

    # ------------------------------------------------------------------ plan
    def scope_signature(self) -> str:
        if self.config.account_ids:
            return "acct:" + ",".join(sorted(self.config.account_ids))
        return "tenant"

    def plan(self, run_id: str, catalog: Catalog, params: RunParams,
             ledger: Ledger) -> int:
        variables = dict(params.variables or {})
        variables.setdefault("entity", params.entity)
        scope = self.scope_signature()
        slices = slices_for_lookback(params.lookback_days, slice_days=params.slice_days)
        ledger.record_run(run_id, params.case_id, params.entity, catalog.name, {
            "lookback_days": params.lookback_days,
            "slice_days": params.slice_days,
            "num_slices": len(slices),
            "max_attempts": params.max_attempts,
            "scope": scope,
        })
        n = 0
        for q in catalog.enabled_queries():
            pq_rendered = q.render(variables)
            for sl in slices:
                jid = make_job_id(run_id, q.id, sl.key, scope)
                ledger.upsert_job(Job(
                    job_id=jid, run_id=run_id, query_id=q.id, slice_key=sl.key,
                    slice_start=sl.start_iso, slice_end=sl.end_iso, scope=scope,
                    pq=pq_rendered))
                n += 1
        self._emit({"event": "planned", "run_id": run_id,
                          "queries": len(catalog.enabled_queries()),
                          "slices": len(slices), "jobs": n})
        return n

    # ------------------------------------------------------------------- run
    def _next_client(self) -> LRQClient:
        with self._rr_lock:
            c = self.clients[self._rr % len(self.clients)]
            self._rr += 1
            return c

    def run(self, run_id: str, ledger: Ledger, params: RunParams) -> Dict[str, Any]:
        reset = ledger.reset_stale_in_flight(run_id)
        if reset:
            self._emit({"event": "resume", "reset_in_flight": reset})
        ledger.set_run_status(run_id, "running")

        # Phase 2: any slice ending at or before the start of the current UTC day
        # is immutable and cacheable; today's partial slice is volatile.
        self._cutoff_iso = iso_z(datetime.now(timezone.utc).replace(
            hour=0, minute=0, second=0, microsecond=0))

        work: "queue.Queue[Optional[Job]]" = queue.Queue()
        pending = ledger.claimable(run_id)
        outstanding = {"n": 0}
        out_lock = threading.Lock()
        stats = {"done": 0, "cached": 0, "failed": 0, "permanent": 0,
                 "throttles": 0, "retries": 0, "subdivided": 0}

        def enqueue(job: Job) -> None:
            with out_lock:
                outstanding["n"] += 1
            work.put(job)

        for j in pending:
            # A prior run may have left FAILED jobs; retry them now with a fresh count.
            if j.state == STATE_FAILED:
                ledger.mark_pending(j.job_id)
                j.state = "pending"
            enqueue(j)

        total = outstanding["n"]
        if total == 0:
            ledger.set_run_status(run_id, "complete")
            return {"stats": stats, "total": 0}

        def worker() -> None:
            while True:
                job = work.get()
                if job is None:
                    work.task_done()
                    return
                try:
                    self._process_job(job, ledger, params, stats, enqueue)
                finally:
                    with out_lock:
                        outstanding["n"] -= 1
                        remaining = outstanding["n"]
                    work.task_done()
                    if remaining == 0:
                        # Wake all workers to exit.
                        for _ in range(self._pool_size):
                            work.put(None)

        threads = [threading.Thread(target=worker, name=f"w{i}", daemon=True)
                   for i in range(self._pool_size)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        cov = ledger.coverage(run_id)
        ledger.set_run_status(run_id, "complete" if cov["complete"] else "incomplete")
        return {"stats": stats, "total": total, "coverage": cov,
                "cache": self.cache.stats()}

    def _process_job(self, job: Job, ledger: Ledger, params: RunParams,
                     stats: Dict[str, int], enqueue: Callable[[Job], None]) -> None:
        # Phase 2: serve immutable past-day slices from the shared cache without
        # touching the backend, the rate budget, or the concurrency limit.
        cacheable = self._cutoff_iso is not None and job.slice_end <= self._cutoff_iso
        ckey = (self.cache.key(job.pq, job.slice_start, job.slice_end, job.scope)
                if (cacheable and self.cache.enabled) else None)
        if ckey:
            hit = self.cache.get(ckey)
            if hit is not None:
                ledger.mark_in_flight(job.job_id)
                path = self._persist_slice(job, hit["columns"], hit["values"],
                                           hit.get("match_count", 0),
                                           hit.get("row_count", len(hit["values"])), 0.0)
                ledger.mark_done(job.job_id, result_path=str(path),
                                 match_count=hit.get("match_count", 0),
                                 row_count=hit.get("row_count", len(hit["values"])),
                                 cpu_ms=0.0)
                stats["cached"] += 1
                self._emit({"event": "slice_cached", "query": job.query_id,
                            "slice": job.slice_key,
                            "rows": hit.get("row_count", len(hit["values"]))})
                return

        client = self._next_client()
        with self.governor.slot():
            ledger.mark_in_flight(job.job_id)
            fresh = ledger.get_job(job.job_id)
            attempts = fresh.attempts if fresh else job.attempts + 1
            try:
                res = client.run_pq(
                    job.pq, job.slice_start, job.slice_end,
                    tenant=self.config.tenant,
                    account_ids=self.config.account_ids or None,
                    priority=params.priority)
            except RateLimitError:
                self.governor.on_throttle()
                stats["throttles"] += 1
                ledger.mark_pending(job.job_id, error="throttled")
                time.sleep(1.0)
                enqueue(ledger.get_job(job.job_id))  # requeue this run
                return
            except QuerySyntaxError as e:
                ledger.mark_permanent(job.job_id, error=str(e)[:500])
                stats["permanent"] += 1
                self._emit({"event": "permanent", "query": job.query_id,
                                  "slice": job.slice_key, "error": str(e)[:200]})
                return
            except ServerError as e:
                self._handle_transient(job, ledger, params, stats, enqueue,
                                       attempts, str(e))
                return
            except LRQError as e:
                self._handle_transient(job, ledger, params, stats, enqueue,
                                       attempts, str(e))
                return

            # Success.
            self.governor.on_success()
            path = self._persist_slice(job, res.columns, res.values,
                                       res.match_count, res.row_count, res.cpu_ms)
            ledger.mark_done(job.job_id, result_path=str(path),
                             match_count=res.match_count, row_count=res.row_count,
                             cpu_ms=res.cpu_ms, lrq_id=res.lrq_id)
            if ckey:  # Phase 2: cache this immutable past-day slice for future runs.
                self.cache.put(ckey, {"columns": res.columns, "values": res.values,
                                      "match_count": res.match_count,
                                      "row_count": res.row_count, "cpu_ms": res.cpu_ms})
            stats["done"] += 1
            self._emit({"event": "slice_done", "query": job.query_id,
                              "slice": job.slice_key, "rows": res.row_count,
                              "match_count": res.match_count,
                              "elapsed_s": round(res.elapsed_s, 2),
                              "client": client.name,
                              "gov_limit": self.governor.limit})

    def _handle_transient(self, job: Job, ledger: Ledger, params: RunParams,
                          stats: Dict[str, int], enqueue: Callable[[Job], None],
                          attempts: int, err: str) -> None:
        if attempts < params.max_attempts:
            stats["retries"] += 1
            ledger.mark_pending(job.job_id, error=err[:500])
            time.sleep(min(2 ** attempts, 15))
            enqueue(ledger.get_job(job.job_id))
            return
        # Retries exhausted. Try one round of subdivision for slow slices.
        if params.subdivide_on_timeout:
            children = self._subdivide_job(job, ledger)
            if children:
                ledger.mark_subdivided(job.job_id)
                stats["subdivided"] += 1
                for c in children:
                    enqueue(c)
                self._emit({"event": "subdivided", "query": job.query_id,
                                  "slice": job.slice_key, "children": len(children)})
                return
        ledger.mark_failed(job.job_id, error=err[:500])
        stats["failed"] += 1
        self._emit({"event": "slice_failed", "query": job.query_id,
                          "slice": job.slice_key, "error": err[:200]})

    def _subdivide_job(self, job: Job, ledger: Ledger) -> List[Job]:
        sl = Slice(datetime.fromisoformat(job.slice_start.replace("Z", "+00:00")),
                   datetime.fromisoformat(job.slice_end.replace("Z", "+00:00")))
        subs = subdivide(sl, factor=4)
        if len(subs) <= 1:
            return []  # already at floor granularity
        children: List[Job] = []
        for s in subs:
            jid = make_job_id(job.run_id, job.query_id, s.key, job.scope)
            child = Job(job_id=jid, run_id=job.run_id, query_id=job.query_id,
                        slice_key=s.key, slice_start=s.start_iso,
                        slice_end=s.end_iso, scope=job.scope, pq=job.pq)
            ledger.upsert_job(child)
            children.append(ledger.get_job(jid) or child)
        return children

    # -------------------------------------------------------------- outputs
    def _persist_slice(self, job: Job, columns: List[str], values: List[List[Any]],
                       match_count: int, row_count: int, cpu_ms: float) -> Path:
        # output_root is the per-run directory; slices live under it by query.
        d = self.output_root / "slices" / _safe(job.query_id)
        d.mkdir(parents=True, exist_ok=True)
        p = d / f"{_safe(job.slice_key)}.json"
        p.write_text(json.dumps({
            "query_id": job.query_id, "slice_key": job.slice_key,
            "slice_start": job.slice_start, "slice_end": job.slice_end,
            "columns": columns, "values": values,
            "match_count": match_count, "row_count": row_count, "cpu_ms": cpu_ms,
        }))
        return p

    def finalize(self, run_id: str, ledger: Ledger, catalog: Catalog,
                 params: RunParams) -> Dict[str, Any]:
        """Merge each query's slice results and write a run manifest."""
        results_dir = self.output_root / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        manifest_queries: List[Dict[str, Any]] = []
        by_id = {q.id: q for q in catalog.queries}

        for q in catalog.enabled_queries():
            all_jobs = ledger.jobs_for_query(run_id, q.id)
            done_jobs = [j for j in all_jobs if j.state == STATE_DONE]
            # The rendered PowerQuery that actually ran (entity substituted) is stored
            # on every job; carry it through so it lands in the results and workbook.
            pq_used = all_jobs[0].pq if all_jobs else q.pq
            slice_results = []
            for j in done_jobs:
                if j.result_path and Path(j.result_path).is_file():
                    slice_results.append(json.loads(Path(j.result_path).read_text()))
            merged, warns = merge_query_results(slice_results, q.merge)
            out_json = results_dir / f"{_safe(q.id)}.json"
            out_json.write_text(json.dumps({
                "query_id": q.id, "title": q.title, "merge_kind": q.merge.kind,
                "pq": pq_used,
                "columns": merged["columns"], "values": merged["values"],
                "warnings": warns,
            }, indent=2))
            _write_csv(results_dir / f"{_safe(q.id)}.csv", merged)
            manifest_queries.append({
                "query_id": q.id, "title": q.title, "pq": pq_used,
                "slices_total": len(all_jobs),
                "slices_done": len(done_jobs),
                "slices_failed": sum(1 for j in all_jobs if j.state == STATE_FAILED),
                "slices_permanent": sum(1 for j in all_jobs if j.state == STATE_PERMANENT),
                "result_rows": len(merged["values"]),
                "warnings": warns,
            })

        cov = ledger.coverage(run_id)
        manifest = {
            "run_id": run_id,
            "case_id": params.case_id,
            "entity": params.entity,
            "catalog": catalog.name,
            "generated_at": iso_z(datetime.now(timezone.utc)),
            "lookback_days": params.lookback_days,
            "slice_days": params.slice_days,
            "scope": self.scope_signature(),
            "complete": cov["complete"],
            "coverage": cov,
            "queries": manifest_queries,
        }
        (self.output_root / "manifest.json").write_text(json.dumps(manifest, indent=2))
        self._emit({"event": "finalized", "complete": cov["complete"],
                          "results_dir": str(results_dir)})
        return manifest

    def write_workbook(self, run_id: str, manifest: Dict[str, Any],
                       verification: Optional[Dict[str, Any]], params: RunParams
                       ) -> Optional[str]:
        """Phase 3: build the per-case .xlsx workbook. Optional; never fails a run."""
        results_dir = self.output_root / "results"
        out = self.output_root / f"{_safe(params.case_id)}_{run_id}.xlsx"
        try:
            path = build_workbook(out, manifest, verification, results_dir)
        except Exception as e:  # noqa: BLE001
            self._emit({"event": "warning", "msg": f"workbook export skipped: {e}"})
            return None
        if path is None:
            self._emit({"event": "warning",
                        "msg": "workbook export skipped (openpyxl not installed)"})
            return None
        self._emit({"event": "workbook", "path": str(path)})
        return str(path)


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in str(name))


def _write_csv(path: Path, table: Dict[str, Any]) -> None:
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(table.get("columns", []))
        for row in table.get("values", []):
            w.writerow(row)
