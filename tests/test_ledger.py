from s1engine.ledger import (Job, Ledger, STATE_DONE, STATE_IN_FLIGHT,
                             STATE_PENDING, job_id)


def _job(run="r1", q="q1", key="2026-01-01"):
    jid = job_id(run, q, key, "tenant")
    return Job(job_id=jid, run_id=run, query_id=q, slice_key=key,
               slice_start="2026-01-01T00:00:00Z", slice_end="2026-01-02T00:00:00Z",
               scope="tenant", pq="dataSource.name=* | limit 1")


def test_upsert_is_idempotent(tmp_path):
    led = Ledger(tmp_path / "l.db")
    j = _job()
    led.upsert_job(j)
    led.mark_done(j.job_id, result_path="/x", match_count=1, row_count=1, cpu_ms=1.0)
    # re-planning must not reset a completed job
    led.upsert_job(j)
    assert led.get_job(j.job_id).state == STATE_DONE
    led.close()


def test_reset_stale_in_flight(tmp_path):
    led = Ledger(tmp_path / "l.db")
    j = _job()
    led.upsert_job(j)
    led.mark_in_flight(j.job_id)
    assert led.get_job(j.job_id).state == STATE_IN_FLIGHT
    n = led.reset_stale_in_flight("r1")
    assert n == 1
    assert led.get_job(j.job_id).state == STATE_PENDING
    led.close()


def test_attempts_increment_on_in_flight(tmp_path):
    led = Ledger(tmp_path / "l.db")
    j = _job()
    led.upsert_job(j)
    led.mark_in_flight(j.job_id)
    led.mark_pending(j.job_id)
    led.mark_in_flight(j.job_id)
    assert led.get_job(j.job_id).attempts == 2
    led.close()


def test_coverage(tmp_path):
    led = Ledger(tmp_path / "l.db")
    for i in range(3):
        j = _job(key=f"2026-01-0{i+1}")
        led.upsert_job(j)
        if i < 2:
            led.mark_done(j.job_id, result_path="/x", match_count=1, row_count=1, cpu_ms=1.0)
    cov = led.coverage("r1")
    assert cov["total_jobs"] == 3
    assert cov["totals_by_state"][STATE_DONE] == 2
    assert cov["complete"] is False  # one still pending
    led.close()
