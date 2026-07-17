"""End-to-end engine tests against the in-memory FakeTransport (no network)."""

from s1engine.activity import ActivityLog
from s1engine.catalog import Catalog, MergeSpec, Query
from s1engine.config import load_config
from s1engine.engine import InvestigationEngine, RunParams
from s1engine.ledger import Ledger, STATE_PERMANENT
from s1engine.testing import FakeTransport
from s1engine.verify import verify_run


AGG_MERGE = MergeSpec(kind="aggregate", key_cols=["event_day"], sum_cols=["hits"],
                      min_cols=["first_seen"], max_cols=["last_seen"])


def _catalog(extra=None):
    queries = [
        Query(id="auth", title="Auth", pq="dataSource.name='X' {{entity}} | group hits=count() by event_day", merge=AGG_MERGE),
        Query(id="files", title="Files", pq="dataSource.name='Y' {{entity}} | columns a,b | limit 10", merge=MergeSpec(kind="rows")),
    ]
    if extra:
        queries.extend(extra)
    return Catalog(name="test", queries=queries)


def _config(**over):
    return load_config(require_credentials=False, console_url="https://mock",
                       tokens=["t1", "t2"], poll_interval_s=0.01,
                       query_timeout_s=5.0, **over)


def _engine(tmp_path, transport, activity=None, pool_size=4):
    return InvestigationEngine(_config(), output_root=tmp_path, transport=transport,
                               pool_size=pool_size, activity=activity)


def test_full_run_passes_and_logs_activity(tmp_path):
    led = Ledger(tmp_path / "ledger.db")
    act = ActivityLog(tmp_path / "activity.jsonl")
    eng = _engine(tmp_path, FakeTransport(), activity=act)
    params = RunParams(case_id="C", entity="alice", lookback_days=2, slice_days=1)
    run_id = "run-1"
    eng.plan(run_id, _catalog(), params, led)
    eng.run(run_id, led, params)
    man = eng.finalize(run_id, led, _catalog(), params)
    v = verify_run(led, run_id, _catalog())
    assert v.passed
    assert v.passed_queries == v.total_queries == 2
    # activity was persisted
    assert (tmp_path / "activity.jsonl").read_text().strip()
    assert ActivityLog.read_file(tmp_path / "activity.jsonl")
    # aggregate query merged per-day; rows query concatenated across slices
    assert man["complete"]
    led.close()
    act.close()


def test_throttles_are_absorbed(tmp_path):
    led = Ledger(tmp_path / "ledger.db")
    eng = _engine(tmp_path, FakeTransport(throttle_first_n=4))
    params = RunParams(case_id="C", entity="bob", lookback_days=2, slice_days=1)
    eng.plan("run-t", _catalog(), params, led)
    result = eng.run("run-t", led, params)
    eng.finalize("run-t", led, _catalog(), params)
    v = verify_run(led, "run-t", _catalog())
    assert v.passed
    assert result["stats"]["throttles"] >= 1
    led.close()


def test_query_syntax_error_is_permanent(tmp_path):
    led = Ledger(tmp_path / "ledger.db")
    broken = Query(id="broken", title="Broken",
                   pq="dataSource.name='Z' BROKEN {{entity}} | limit 1",
                   merge=MergeSpec(kind="rows"))
    cat = _catalog(extra=[broken])
    eng = _engine(tmp_path, FakeTransport(fail_query_substr={"BROKEN": "syntax"}))
    params = RunParams(case_id="C", entity="carol", lookback_days=1, slice_days=1)
    eng.plan("run-p", cat, params, led)
    eng.run("run-p", led, params)
    eng.finalize("run-p", led, cat, params)
    v = verify_run(led, "run-p", cat)
    assert not v.passed
    # the two good queries still pass; only the broken one fails
    by_id = {q.query_id: q for q in v.queries}
    assert by_id["auth"].status == "pass"
    assert by_id["broken"].status == "failed"
    perm = led.jobs_for_query("run-p", "broken", state=STATE_PERMANENT)
    assert len(perm) >= 1
    led.close()


def _broken_cat():
    return Catalog(name="brk", queries=[
        Query(id="broken", title="Broken",
              pq="dataSource.name='Z' BROKEN {{entity}} | limit 1",
              merge=MergeSpec(kind="rows"))])


def _fast_engine(tmp_path, transport, pool_size=4):
    # High rps so the rate limiter is not a timing factor in these tests.
    cfg = load_config(require_credentials=False, console_url="https://mock",
                      tokens=["t1", "t2"], poll_interval_s=0.001, query_timeout_s=5.0,
                      rps=10000.0, burst=10000)
    return InvestigationEngine(cfg, output_root=tmp_path, transport=transport,
                               pool_size=pool_size)


def test_permanent_error_aborts_remaining_slices_of_query(tmp_path):
    led = Ledger(tmp_path / "ledger.db")
    cat = _broken_cat()
    # Many slices (> worker pool) so the breaker demonstrably skips some of them.
    eng = _fast_engine(tmp_path, FakeTransport(fail_query_substr={"BROKEN": "syntax"}))
    params = RunParams(case_id="C", entity="dave", lookback_days=15, slice_days=1,
                       abort_query_on_permanent=True)
    eng.plan("run-cb", cat, params, led)
    result = eng.run("run-cb", led, params)
    broken_total = sum(result["coverage"]["per_query"]["broken"].values())
    # Some slices were rejected, and the breaker skipped the rest instead of re-failing.
    assert result["stats"]["permanent"] >= 1
    assert result["stats"]["aborted"] >= 1
    assert result["stats"]["permanent"] < broken_total          # the breaker saved slices
    assert result["stats"]["permanent"] + result["stats"]["aborted"] == broken_total
    v = verify_run(led, "run-cb", cat)
    assert {q.query_id: q.status for q in v.queries}["broken"] == "failed"
    assert result["coverage"]["complete"]                        # no slices left pending
    led.close()


def test_abort_disabled_attempts_every_slice(tmp_path):
    led = Ledger(tmp_path / "ledger.db")
    cat = _broken_cat()
    eng = _fast_engine(tmp_path, FakeTransport(fail_query_substr={"BROKEN": "syntax"}))
    params = RunParams(case_id="C", entity="erin", lookback_days=6, slice_days=1,
                       abort_query_on_permanent=False)
    eng.plan("run-nb", cat, params, led)
    result = eng.run("run-nb", led, params)
    broken_total = sum(result["coverage"]["per_query"]["broken"].values())
    # With the breaker off, every slice is attempted and permanently fails.
    assert result["stats"]["aborted"] == 0
    assert result["stats"]["permanent"] == broken_total
    led.close()


def test_resume_retries_failed_slices_on_second_run(tmp_path):
    led = Ledger(tmp_path / "ledger.db")
    flaky = Query(id="flaky", title="Flaky",
                  pq="dataSource.name='W' FLAKY {{entity}} | limit 1",
                  merge=MergeSpec(kind="rows"))
    cat = _catalog(extra=[flaky])
    run_id = "run-r"
    params = RunParams(case_id="C", entity="dan", lookback_days=1, slice_days=1,
                       max_attempts=1, subdivide_on_timeout=False)

    # Run 1: the flaky query's slices fail (server errors), so the run is incomplete.
    eng1 = _engine(tmp_path, FakeTransport(fail_query_substr={"FLAKY": "server"}))
    eng1.plan(run_id, cat, params, led)
    eng1.run(run_id, led, params)
    v1 = verify_run(led, run_id, cat)
    assert not v1.passed

    # Run 2: same ledger + run id, a healthy backend. Only the failed slices re-run;
    # the already-done slices are skipped (resume + cache behaviour).
    eng2 = _engine(tmp_path, FakeTransport())
    eng2.plan(run_id, cat, params, led)     # idempotent: does not reset done work
    eng2.run(run_id, led, params)
    eng2.finalize(run_id, led, cat, params)
    v2 = verify_run(led, run_id, cat)
    assert v2.passed
    led.close()


def test_cancel_leaves_slices_pending_and_is_resumable(tmp_path):
    led = Ledger(tmp_path / "ledger.db")
    run_id = "run-c"
    params = RunParams(case_id="C", entity="erin", lookback_days=2, slice_days=1)

    # Cancel before any slice runs: everything stays pending, run reports cancelled.
    eng = _engine(tmp_path, FakeTransport())
    eng.plan(run_id, _catalog(), params, led)
    eng.request_cancel()
    result = eng.run(run_id, led, params)
    assert result["cancelled"] is True
    assert result["stats"]["done"] == 0
    assert not verify_run(led, run_id, _catalog()).passed

    # Resume with a fresh engine (no cancel): the pending slices complete.
    eng2 = _engine(tmp_path, FakeTransport())
    eng2.run(run_id, led, params)
    eng2.finalize(run_id, led, _catalog(), params)
    assert verify_run(led, run_id, _catalog()).passed
    led.close()
