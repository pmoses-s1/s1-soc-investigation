"""
Activity log: an append-only, structured record of everything the engine does.

Every event (plan, slice submitted, slice done, retry, throttle, subdivide,
failure, finalize) is written as one JSON line to activity.jsonl in the run
directory and kept in an in-memory ring buffer with a monotonic sequence number.
The UI polls tail(since_seq) for a live feed; the file is the durable audit
trail an analyst (or an auditor) can read after the fact to confirm exactly
which queries ran and how they completed.
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional


class ActivityLog:
    def __init__(self, path: str | Path, ring_size: int = 5000):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._seq = 0
        self._ring: List[Dict[str, Any]] = []
        self._ring_size = ring_size
        self._subscribers: List[Callable[[Dict[str, Any]], None]] = []
        self._fh = open(self.path, "a", buffering=1)  # line-buffered

    def log(self, event: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            self._seq += 1
            rec = dict(event)
            rec.setdefault("event", "message")
            rec["seq"] = self._seq
            rec["ts"] = time.time()
            self._fh.write(json.dumps(rec, default=str) + "\n")
            self._ring.append(rec)
            if len(self._ring) > self._ring_size:
                self._ring = self._ring[-self._ring_size:]
            subs = list(self._subscribers)
        for fn in subs:
            try:
                fn(rec)
            except Exception:
                pass
        return rec

    def tail(self, since_seq: int = 0, limit: int = 1000) -> List[Dict[str, Any]]:
        with self._lock:
            out = [r for r in self._ring if r["seq"] > since_seq]
        return out[:limit]

    def last_seq(self) -> int:
        with self._lock:
            return self._seq

    def subscribe(self, fn: Callable[[Dict[str, Any]], None]) -> None:
        with self._lock:
            self._subscribers.append(fn)

    def close(self) -> None:
        with self._lock:
            try:
                self._fh.close()
            except Exception:
                pass

    @staticmethod
    def read_file(path: str | Path) -> List[Dict[str, Any]]:
        """Load a persisted activity.jsonl (for the UI to render a past run)."""
        p = Path(path)
        if not p.is_file():
            return []
        out: List[Dict[str, Any]] = []
        for line in p.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
