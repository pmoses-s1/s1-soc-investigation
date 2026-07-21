"""Scope classification + gating, and wall-timeout handling.

Covers the three behaviours added for the subject-scoping and slice-timeout work:
  * the catalog scope model (subject/pivot/environment/coverage) and its gate,
  * plan() hard-skipping a subject query with no populated subject value,
  * a wall timeout subdividing immediately instead of retrying the same slice.
"""

from s1engine.catalog import Catalog, MergeSpec, Query, load_catalog
from s1engine.config import load_config
from s1engine.engine import InvestigationEngine, RunParams
from s1engine.ledger import Ledger, Job, STATE_PENDING, job_id
from s1engine.testing import FakeTransport


# --------------------------------------------------------------- scope model
def test_effective_scope_inference():
    subj = Query(id="s", title="s", pq="dataSource.name='X' event.user contains:anycase('{{entity}}')")
    piv = Query(id="p", title="p", pq="dataSource.name='X' url contains '{{domain}}'")
    env = Query(id="e", title="e", pq="dataSource.name='X' | group c=count()")
    assert subj.effective_scope() == "subject"
    assert piv.effective_scope() == "pivot"
    assert env.effective_scope() == "environment"
    # An explicit scope always wins over inference.
    env2 = Query(id="e2", title="e2", pq="dataSource.name='X' {{entity}}", scope="coverage")
    assert env2.effective_scope() == "coverage"


def test_scope_gate_subject():
    q = Query(id="s", title="s",
              pq="dataSource.name='X' event.user contains:anycase('{{entity}}')")
    # No subject value provided -> gated with a clear reason.
    g = q.scope_gate({})
    assert g and g["reason"] == "no_subject_value" and "entity" in g["needs"]
    # Subject value present -> allowed to run.
    assert q.scope_gate({"entity": "subject-user"}) is None


def test_scope_gate_subject_without_any_filter_is_blocked():
    # scope=subject but the body never filters on a subject var (the exact leak):
    # it must not run tenant-wide.
    q = Query(id="leak", title="All Raw", pq="serverHost='zia' | columns event.user | limit 100",
              scope="subject")
    g = q.scope_gate({"entity": "subject-user"})
    assert g and g["reason"] == "subject_scope_no_filter"


def test_environment_and_coverage_never_gated():
    env = Query(id="e", title="e", pq="serverHost='zia' | group users=estimate_distinct(event.user)",
                scope="environment")
    cov = Query(id="c", title="c", pq="dataSource.name=* | group by serverHost", scope="coverage")
    assert env.scope_gate({}) is None
    assert cov.scope_gate({}) is None


def test_bundled_catalogs_are_scope_clean():
    """No bundled query may be scope=subject/pivot without a matching filter, so
    nothing can silently run tenant-wide. Guards against reintroducing the leak."""
    import glob
    from s1engine.lint import scope_issues
    offenders = {}
    for f in sorted(glob.glob("catalogs/dfir_*.yaml")) + ["catalogs/insider_threat.yaml"]:
        try:
            issues = scope_issues(load_catalog(f))
        except FileNotFoundError:
            continue
        if issues:
            offenders[f] = issues
    assert not offenders, f"scope-authoring issues (would run tenant-wide): {offenders}"


def test_load_catalog_rejects_invalid_scope(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("name: bad\nqueries:\n- id: q1\n  pq: \"dataSource.name='X' {{entity}}\"\n  scope: banana\n")
    try:
        load_catalog(p)
        raise AssertionError("expected ValueError for invalid scope")
    except ValueError:
        pass


def test_scope_counts(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(
        "name: c\nqueries:\n"
        "- id: a\n  pq: \"serverHost='zia' event.user contains:anycase('{{entity}}')\"\n  scope: subject\n"
        "- id: b\n  pq: \"serverHost='zia' | group c=count()\"\n  scope: environment\n"
        "- id: d\n  pq: \"dataSource.name=* | group by serverHost\"\n  scope: coverage\n")
    counts = load_catalog(p).scope_counts()
    assert counts["subject"] == 1 and counts["environment"] == 1 and counts["coverage"] == 1


# ----------------------------------------------------------- plan() gating
def _config(**over):
    over.setdefault("rps", 10000.0)
    over.setdefault("burst", 10000)
    return load_config(require_credentials=False, console_url="https://mock",
                       tokens=["t1"], poll_interval_s=0.01, query_timeout_s=5.0, **over)


def test_plan_skips_subject_query_without_value_and_runs_environment(tmp_path):
    events = []
    eng = InvestigationEngine(_config(), output_root=tmp_path, transport=FakeTransport(),
                              on_progress=events.append)
    # env query (no subject var) should run; subject query filtered on {{ip}} (a
    # non-empty default, so the required-var check does NOT catch it) should be
    # skipped by the scope gate specifically, with reason 'no_subject_value',
    # because ip is not set for this run.
    cat = Catalog(name="t", queries=[
        Query(id="env", title="Top", pq="dataSource.name='X' | group c=count()",
              scope="environment", merge=MergeSpec(kind="rows")),
        Query(id="subj", title="By IP", pq="dataSource.name='X' src.ip.address=='{{ip|0.0.0.0}}' | limit 5",
              scope="subject", merge=MergeSpec(kind="rows")),
    ])
    led = Ledger(tmp_path / "ledger.db")
    eng.plan("r", cat, RunParams(case_id="C", entity="alice", lookback_days=1, slice_days=1), led)
    planned = [e for e in events if e.get("event") == "planned"][-1]
    assert planned["queries"] == 1 and planned["skipped"] == 1  # only env is runnable
    skips = [e for e in events if e.get("event") == "query_skipped"]
    assert any(s["query"] == "subj" and s.get("reason") == "no_subject_value" for s in skips)
    # And with ip provided, the subject query becomes runnable too.
    events.clear()
    led2 = Ledger(tmp_path / "ledger2.db")
    eng.plan("r2", cat, RunParams(case_id="C", entity="alice", lookback_days=1,
                                  slice_days=1, variables={"ip": "10.0.0.1"}), led2)
    planned2 = [e for e in events if e.get("event") == "planned"][-1]
    assert planned2["queries"] == 2 and planned2["skipped"] == 0
    led.close(); led2.close()


# ---------------------------------------------------- wall-timeout handling
def _one_day_job(run_id="r", qid="heavy"):
    return Job(job_id=job_id(run_id, qid, "2026-03-20", "sig"), run_id=run_id, query_id=qid,
               slice_key="2026-03-20", slice_start="2026-03-20T00:00:00Z",
               slice_end="2026-03-21T00:00:00Z", scope="sig",
               pq="serverHost='zia' | limit 1", state=STATE_PENDING)


def test_wall_timeout_subdivides_immediately(tmp_path):
    eng = InvestigationEngine(_config(), output_root=tmp_path, transport=FakeTransport())
    led = Ledger(tmp_path / "ledger.db")
    job = _one_day_job()
    led.upsert_job(job)
    stats = {"retries": 0, "subdivided": 0, "failed": 0}
    children = []
    eng._handle_transient(job, led, RunParams(case_id="C", entity="x"), stats,
                          children.append, attempts=1,
                          err="slice exceeded 120.0s wall timeout", timeout=True)
    # A wall timeout skips the same-size retry loop and subdivides on the first hit.
    assert stats["retries"] == 0
    assert stats["subdivided"] == 1
    assert len(children) == 4  # one day -> four 6h sub-slices
    led.close()


def test_transient_error_retries_before_subdividing(tmp_path):
    eng = InvestigationEngine(_config(), output_root=tmp_path, transport=FakeTransport())
    led = Ledger(tmp_path / "ledger.db")
    job = _one_day_job(qid="blip")
    led.upsert_job(job)
    stats = {"retries": 0, "subdivided": 0, "failed": 0}
    children = []
    eng._handle_transient(job, led, RunParams(case_id="C", entity="x"), stats,
                          children.append, attempts=1,
                          err="server error (injected)", timeout=False)
    # A genuine transient error retries the same slice first (no subdivision yet).
    assert stats["retries"] == 1
    assert stats["subdivided"] == 0
    assert len(children) == 1 and children[0].job_id == job.job_id
    led.close()
