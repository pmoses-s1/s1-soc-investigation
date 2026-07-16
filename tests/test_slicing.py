from datetime import datetime, timezone

from s1engine.slicing import Slice, day_slices, slices_for_lookback, subdivide


def test_day_slices_count_and_clip():
    start = datetime(2026, 1, 1, 9, 30, tzinfo=timezone.utc)
    end = datetime(2026, 1, 4, 6, 0, tzinfo=timezone.utc)
    sls = day_slices(start, end, slice_days=1)
    # partial first day, two full days, partial last day
    assert len(sls) == 4
    assert sls[0].start == start          # clipped to true start
    assert sls[-1].end == end             # clipped to true end
    # slices are contiguous and non-overlapping
    for a, b in zip(sls, sls[1:]):
        assert a.end == b.start


def test_slice_key_is_date_for_full_day():
    sls = day_slices(datetime(2026, 1, 1, tzinfo=timezone.utc),
                     datetime(2026, 1, 2, tzinfo=timezone.utc))
    assert len(sls) == 1
    assert sls[0].key == "2026-01-01"


def test_multi_day_slice_size():
    sls = day_slices(datetime(2026, 1, 1, tzinfo=timezone.utc),
                     datetime(2026, 1, 11, tzinfo=timezone.utc), slice_days=3)
    # 10 days / 3 -> 4 slices (3,3,3,1)
    assert len(sls) == 4


def test_lookback_slices():
    now = datetime(2026, 6, 30, 12, 0, tzinfo=timezone.utc)
    sls = slices_for_lookback(7, now=now, slice_days=1)
    total = sum(s.duration_s for s in sls)
    assert abs(total - 7 * 86400) < 1.0


def test_subdivide():
    sl = Slice(datetime(2026, 1, 1, tzinfo=timezone.utc),
               datetime(2026, 1, 2, tzinfo=timezone.utc))
    subs = subdivide(sl, factor=4)
    assert len(subs) == 4
    assert subs[0].start == sl.start
    assert subs[-1].end == sl.end
    # at the 1h floor, subdivision stops
    small = Slice(datetime(2026, 1, 1, 0, 0, tzinfo=timezone.utc),
                  datetime(2026, 1, 1, 1, 0, tzinfo=timezone.utc))
    assert subdivide(small, factor=4) == [small]
