import time

from s1engine.rate_limiter import AIMDController, TokenBucket


def test_token_bucket_enforces_rate():
    b = TokenBucket(rps=20, burst=1)
    t0 = time.monotonic()
    for _ in range(5):
        b.acquire()
    elapsed = time.monotonic() - t0
    # 5 tokens at 20 rps with burst 1 -> at least ~4/20 = 0.2s of waiting
    assert elapsed >= 0.15


def test_aimd_decrease_and_increase():
    c = AIMDController(initial=4, minimum=1, maximum=8, increase_after=2)
    assert c.limit == 4
    c.on_throttle()
    assert c.limit == 2          # multiplicative decrease
    c.on_throttle()
    assert c.limit == 1          # floored at minimum
    c.on_success()
    c.on_success()
    assert c.limit == 2          # additive increase after streak
    c.on_throttle()
    assert c.limit == 1          # decrease resets the streak too


def test_aimd_slot_limits_concurrency():
    c = AIMDController(initial=1, minimum=1, maximum=1)
    entered = []
    with c.slot():
        entered.append(c.snapshot()["active"])
    assert entered == [1]
