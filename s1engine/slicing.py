"""
Time-slicing: turn a lookback window into a list of independent slices.

Slices are aligned to UTC calendar-day boundaries so that a given (query, day)
pair is deterministic and, for any day in the past, immutable. That immutability
is what makes the slice key a stable cache key in later phases.

The first and last slices are clipped to the actual start/end so a "90 day"
lookback that starts mid-day does not silently query a partial extra day.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional


def iso_z(dt: datetime) -> str:
    """Format a UTC datetime as ISO-8601 with a Z suffix (LRQ wire format)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass(frozen=True)
class Slice:
    start: datetime  # inclusive, UTC
    end: datetime    # exclusive, UTC

    @property
    def key(self) -> str:
        """Stable slice identifier. Day-aligned slices read as a date range."""
        s = self.start.astimezone(timezone.utc)
        e = self.end.astimezone(timezone.utc)
        if _is_midnight(s) and _is_midnight(e) and (e - s) == timedelta(days=1):
            return s.strftime("%Y-%m-%d")
        return f"{iso_z(s)}__{iso_z(e)}"

    @property
    def start_iso(self) -> str:
        return iso_z(self.start)

    @property
    def end_iso(self) -> str:
        return iso_z(self.end)

    @property
    def duration_s(self) -> float:
        return (self.end - self.start).total_seconds()


def _is_midnight(dt: datetime) -> bool:
    return dt.hour == 0 and dt.minute == 0 and dt.second == 0 and dt.microsecond == 0


def _floor_day(dt: datetime) -> datetime:
    dt = dt.astimezone(timezone.utc)
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


def day_slices(start: datetime, end: datetime, slice_days: int = 1) -> List[Slice]:
    """Split [start, end) into slices of `slice_days`, aligned to UTC midnight.

    First/last slices are clipped to the true start/end.
    """
    if slice_days < 1:
        raise ValueError("slice_days must be >= 1")
    start = start.astimezone(timezone.utc)
    end = end.astimezone(timezone.utc)
    if end <= start:
        return []

    slices: List[Slice] = []
    # Begin at the aligned day boundary at or before start, then clip.
    cursor = _floor_day(start)
    step = timedelta(days=slice_days)
    while cursor < end:
        seg_start = max(cursor, start)
        seg_end = min(cursor + step, end)
        if seg_end > seg_start:
            slices.append(Slice(seg_start, seg_end))
        cursor += step
    return slices


def slices_for_lookback(
    lookback_days: int,
    now: Optional[datetime] = None,
    slice_days: int = 1,
) -> List[Slice]:
    """Build slices for the last `lookback_days` ending at `now` (default: utcnow)."""
    now = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    start = now - timedelta(days=lookback_days)
    return day_slices(start, now, slice_days=slice_days)


def subdivide(sl: Slice, factor: int = 4, min_seconds: float = 3600.0) -> List[Slice]:
    """Split a slice into `factor` equal sub-slices for adaptive retry.

    Returns [sl] unchanged if it is already at or below `min_seconds`, so callers
    can stop subdividing a slice that still times out at the floor granularity.
    """
    if factor < 2 or sl.duration_s <= min_seconds:
        return [sl]
    n = factor
    total = sl.end - sl.start
    step = total / n
    out: List[Slice] = []
    for i in range(n):
        seg_start = sl.start + step * i
        seg_end = sl.end if i == n - 1 else sl.start + step * (i + 1)
        out.append(Slice(seg_start, seg_end))
    return out
