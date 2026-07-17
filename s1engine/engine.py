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
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
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
from .slicing import Slice, day_slices, iso_z, slices_for_lookback, subdivide
from .workbook import build_workbook

_SERVERHOST_RE = re.compile(r"serverHost\s*=\s*'([^']+)'")
_DATASOURCE_RE = re.compile(r"dataSource\.name\s*=\s*'([^']+)'")


def _apply_source_field(pq: str, field: Optional[str]) -> str:
    """Force every source-anchor predicate to `field` (serverHost or dataSource.name).

    Only rewrites the field name when it is the anchor (immediately followed by `=`
    or `in`), so `| group ... by dataSource.name` and similar projections are left
    alone. None leaves the query as authored."""
    if field not in ("serverHost", "dataSource.name"):
        return pq
    other = "dataSource.name" if field == "serverHost" else "serverHost"
    pq = re.sub(r"\b" + re.escape(other) + r"\s*=", field + "=", pq)
    pq = re.sub(r"\b" + re.escape(other) + r"\s+in\b", field + " in", pq)
    return pq


def _query_source(pq: str):
    """The (field, value) a query anchors its source to, or None.

    A query can pin its source with `serverHost='X'` OR `dataSource.name='X'`
    (which one is populated varies by source/query). Returns the single anchor if
    exactly one field/value is used; returns None for multi-source (`... in (...)`),
    both-fields, or source-agnostic queries so they are never pre-checked."""
    if re.search(r"serverHost\s+in\b", pq) or re.search(r"dataSource\.name\s+in\b", pq):
        return None
    sh = _SERVERHOST_RE.findall(pq)
    dsn = _DATASOURCE_RE.findall(pq)
    if len(sh) == 1 and not dsn:
        return ("serverHost", sh[0])
    if len(dsn) == 1 and not sh:
        return ("dataSource.name", dsn[0])
    return None


ProgressFn = Callable[[Dict[str, Any]], None]


@dataclass
class RunParams:
    case_id: str
    entity: str
    lookback_days: int = 90
    slice_days: int = 1
    max_attempts: int = 4
    subdivide_on_timeout: bool = True
    priority: str = "LOW"
    variables: Optional[Dict[str, str]] = None
    start_date: Optional[str] = None   # "YYYY-MM-DD" (inclusive), overrides lookback_days
    end_date: Optional[str] = None     # "YYYY-MM-DD" (inclusive)
    # Circuit breaker: once a query is rejected with a permanent (syntax/400) error,
    # a syntax error is deterministic for the whole query, so skip its remaining
    # slices instead of re-failing every day and wasting the rate budget.
    abort_query_on_permanent: bool = True
    # Source-existence pre-check: for a query anchored to one serverHost source,
    # probe that source once per day and skip the query's slice as empty if the
    # source has no data that day (instead of launching many empty-day queries).
    precheck_source_existence: bool = True
    # Optionally rewrite the source-anchor field across all queries. Some tenants
    # populate serverHost, others dataSource.name. None = use each query as written;
    # "serverHost" / "dataSource.name" = force every anchor predicate to that field.
    source_field: Optional[str] = None


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
        # Cooperative cancel: set from another thread to stop launching new slices.
        self._cancel = threading.Event()

    def request_cancel(self) -> None:
        """Signal a cooperative stop. In-flight slices finish; no new ones start.
        Pending slices are left pending, so the run stays fully resumable."""
        if not self._cancel.is_set():
            self._cancel.set()
            self._emit({"event": "cancelling"})

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
        if params.start_date and params.end_date:
            # Absolute window (e.g. all of April): end_date is inclusive, so the
            # exclusive upper bound is the day after.
            s = datetime.fromisoformat(params.start_date).replace(tzinfo=timezone.utc)
            e = datetime.fromisoformat(params.end_date).replace(tzinfo=timezone.utc) + timedelta(days=1)
            slices = day_slices(s, e, slice_days=params.slice_days)
            window = {"start_date": params.start_date, "end_date": params.end_date}
        else:
            slices = slices_for_lookback(params.lookback_days, slice_days=params.slice_days)
            window = {"lookback_days": params.lookback_days}
        ledger.record_run(run_id, params.case_id, params.entity, catalog.name, {
            **window,
            "slice_days": params.slice_days,
            "num_slices": len(slices),
            "max_attempts": params.max_attempts,
            "scope": scope,
        })
        provided = {k for k, v in variables.items() if str(v).strip()}
        n = 0
        runnable = 0
        skipped = []
        for q in catalog.enabled_queries():
            missing = [v for v in q.required_vars() if v not in provided]
            if missing:
                # Skip a query whose template variables are not set (e.g. an
                # endpoint query needing {{hostname}} run in the identity phase).
                # It creates no jobs and is reported as skipped, not failed.
                skipped.append({"query": q.id, "missing": missing})
                self._emit({"event": "query_skipped", "query": q.id, "missing": missing})
                continue
            runnable += 1
            pq_rendered = _apply_source_field(q.render(variables), params.source_field)
            for sl in slices:
                jid = make_job_id(run_id, q.id, sl.key, scope)
                ledger.upsert_job(Job(
                    job_id=jid, run_id=run_id, query_id=q.id, slice_key=sl.key,
                    slice_start=sl.start_iso, slice_end=sl.end_iso, scope=scope,
                    pq=pq_rendered))
                n += 1
        self._emit({"event": "planned", "run_id": run_id,
                          "queries": runnable, "skipped": len(skipped),
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
                 "throttles": 0, "retries": 0, "subdivided": 0, "aborted": 0,
                 "skipped_empty": 0}
        # Circuit breaker state: query_id -> the permanent error that tripped it.
        # Reset per run so a resume re-evaluates the query.
        self._broken: Dict[str, str] = {}
        self._broken_lock = threading.Lock()
        # Source-existence cache for the day pre-check: (source, slice_key) -> bool,
        # with per-key in-flight events so each (source, day) is probed only once.
        self._src_exist: Dict[tuple, bool] = {}
        self._src_inflight: Dict[tuple, threading.Event] = {}
        self._warned_mismatch: set = set()
        self._src_lock = threading.Lock()

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
                    if self._cancel.is_set():
                        pass  # cancel requested: leave this job pending (resumable)
                    else:
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
        cancelled = self._cancel.is_set()
        status = "cancelled" if cancelled else ("complete" if cov["complete"] else "incomplete")
        ledger.set_run_status(run_id, status)
        if cancelled:
            self._emit({"event": "cancelled", "done": stats["done"]})
        return {"stats": stats, "total": total, "coverage": cov,
                "cache": self.cache.stats(), "cancelled": cancelled}

    def _process_job(self, job: Job, ledger: Ledger, params: RunParams,
                     stats: Dict[str, int], enqueue: Callable[[Job], None]) -> None:
        # Circuit breaker: if this query already hit a permanent (syntax/400) error
        # on another slice, skip the rest of its slices instead of re-failing each
        # day. Marks them terminal (permanent) so coverage still completes.
        if params.abort_query_on_permanent:
            with self._broken_lock:
                reason = self._broken.get(job.query_id)
            if reason is not None:
                ledger.mark_permanent(job.job_id,
                                      error=f"aborted: query failed earlier and needs a fix ({reason})")
                stats["aborted"] += 1
                self._emit({"event": "slice_aborted", "query": job.query_id,
                            "slice": job.slice_key})
                return
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

        # Source-existence pre-check: if this query is anchored to a single serverHost
        # source and that source has no data for this day, record an empty result
        # instead of launching (one probe per source per day serves all its queries).
        if params.precheck_source_existence and not self._cancel.is_set():
            src = _query_source(job.pq)
            if src is not None:
                field, value = src
                other_field = "dataSource.name" if field == "serverHost" else "serverHost"
                skip = False
                skip_other = None
                if not self._field_has_data(field, value, job, params):
                    # Used field is empty; probe the other field to tell "empty day"
                    # from "data is under the other field" (query anchored wrong).
                    if self._field_has_data(other_field, value, job, params):
                        skip = True
                        skip_other = other_field
                        self._warn_field_mismatch(value, field, other_field)
                    else:
                        skip = True
                if skip:
                    ledger.mark_in_flight(job.job_id)
                    path = self._persist_slice(job, [], [], 0, 0, 0.0)
                    ledger.mark_done(job.job_id, result_path=str(path), match_count=0,
                                     row_count=0, cpu_ms=0.0)
                    stats["skipped_empty"] += 1
                    ev = {"event": "slice_skipped_empty", "query": job.query_id,
                          "slice": job.slice_key, "source": value}
                    if skip_other:
                        ev["other_field"] = skip_other
                    self._emit(ev)
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
                self._emit({"event": "throttled", "query": job.query_id,
                            "slice": job.slice_key, "gov_limit": self.governor.limit})
                time.sleep(1.0)
                enqueue(ledger.get_job(job.job_id))  # requeue this run
                return
            except QuerySyntaxError as e:
                ledger.mark_permanent(job.job_id, error=str(e)[:500])
                stats["permanent"] += 1
                self._emit({"event": "permanent", "query": job.query_id,
                                  "slice": job.slice_key, "error": str(e)[:200]})
                # Trip the circuit breaker for this query so its remaining slices
                # are skipped rather than each re-hitting the same syntax error.
                if params.abort_query_on_permanent:
                    with self._broken_lock:
                        first = job.query_id not in self._broken
                        self._broken[job.query_id] = str(e)[:200]
                    if first:
                        self._emit({"event": "query_aborted", "query": job.query_id,
                                    "error": str(e)[:200]})
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

    def _field_has_data(self, field: str, value: str, job: Job, params: RunParams) -> bool:
        """Whether `field='value'` has any data in this day-slice. Probed once per
        (field, value, slice) and cached; concurrent jobs wait on the first probe.
        Fails open (True) on error so a probe never drops a real query.

        Probing is lazy: callers check the query's own field first and only probe the
        other field if the first is empty, so the common (data present) case costs a
        single probe shared across every query for that source that day."""
        key = (field, value, job.slice_key, job.scope)
        with self._src_lock:
            if key in self._src_exist:
                return self._src_exist[key]
            ev = self._src_inflight.get(key)
            owner = ev is None
            if owner:
                ev = threading.Event()
                self._src_inflight[key] = ev
        if not owner:
            ev.wait(timeout=120)
            return self._src_exist.get(key, True)
        has = True
        try:
            with self.governor.slot():
                res = self._next_client().run_pq(
                    f"{field}='{value}' | limit 1", job.slice_start, job.slice_end,
                    tenant=self.config.tenant,
                    account_ids=self.config.account_ids or None,
                    priority=params.priority)
            has = (res.row_count > 0) or (res.match_count > 0)
        except Exception:  # noqa: BLE001 - fail open; never drop real queries
            has = True
        with self._src_lock:
            self._src_exist[key] = has
            ev.set()
        return has

    def _warn_field_mismatch(self, value: str, used: str, other: str) -> None:
        """Emit a one-time warning that a source exists under a different field than
        the query uses (e.g. query says serverHost='Okta' but data is in
        dataSource.name='Okta')."""
        k = (value, used)
        with self._src_lock:
            if k in self._warned_mismatch:
                return
            self._warned_mismatch.add(k)
        self._emit({"event": "source_field_mismatch", "source": value,
                    "used_field": used, "other_field": other})

    def _handle_transient(self, job: Job, ledger: Ledger, params: RunParams,
                          stats: Dict[str, int], enqueue: Callable[[Job], None],
                          attempts: int, err: str) -> None:
        if attempts < params.max_attempts:
            stats["retries"] += 1
            ledger.mark_pending(job.job_id, error=err[:500])
            self._emit({"event": "retry", "query": job.query_id, "slice": job.slice_key,
                        "attempt": attempts, "error": err[:120]})
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
        # Retries AND subdivision are both exhausted and the slice still failed.
        # A transient blip would have recovered by now, so this is a deterministic
        # query error (e.g. a 500 from a malformed query). Trip the circuit breaker
        # so the query's remaining slices are skipped, and flag that it needs a fix.
        if params.abort_query_on_permanent:
            with self._broken_lock:
                first = job.query_id not in self._broken
                self._broken[job.query_id] = err[:200]
            if first:
                self._emit({"event": "query_needs_fix", "query": job.query_id,
                            "error": err[:200]})

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
        provided = {"entity"} if params.entity else set()
        provided |= {k for k, v in (params.variables or {}).items() if str(v).strip()}

        for q in catalog.enabled_queries():
            all_jobs = ledger.jobs_for_query(run_id, q.id)
            if not all_jobs:
                # No jobs planned = skipped because required template vars were unset.
                missing = [v for v in q.required_vars() if v not in provided]
                manifest_queries.append({
                    "query_id": q.id, "title": q.title, "pq": q.pq,
                    "status": "skipped", "missing_vars": missing,
                    "slices_total": 0, "slices_done": 0, "slices_failed": 0,
                    "slices_permanent": 0, "result_rows": 0, "warnings": []})
                continue
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
