"""
Phase 2: content-addressed slice cache.

A past UTC calendar day's result for a given query never changes, so it can be
cached forever and reused across runs and even across different investigations.
The cache key is a hash of the normalized query body, the slice window, the
account scope, and a schema version, so any run asking the same question of the
same day reads the cached answer instead of re-querying the Data Lake.

Only immutable slices are cached: a slice whose end is at or before the start of
the current UTC day. Today's partial slice is volatile and always re-runs. This
is what makes re-running an investigation, or a second overlapping one, execute
only the missing/volatile slices.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from pathlib import Path
from typing import Any, Dict, Optional

# Bump when the result shape or normalization changes so old entries are ignored.
SCHEMA_VERSION = "v1"

_WS = re.compile(r"\s+")


def _normalize_pq(pq: str) -> str:
    """Collapse whitespace so cosmetically different but identical queries share a key."""
    return _WS.sub(" ", pq).strip()


class SliceCache:
    def __init__(self, root: str | Path, enabled: bool = True):
        self.enabled = enabled
        self.root = Path(root)
        self._lock = threading.Lock()
        self.hits = 0
        self.writes = 0
        if self.enabled:
            self.root.mkdir(parents=True, exist_ok=True)

    def key(self, pq: str, start_iso: str, end_iso: str, scope: str) -> str:
        raw = "\x1f".join([SCHEMA_VERSION, _normalize_pq(pq), start_iso, end_iso, scope])
        return hashlib.sha256(raw.encode()).hexdigest()

    def _path(self, key: str) -> Path:
        return self.root / key[:2] / f"{key}.json"

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        if not self.enabled:
            return None
        p = self._path(key)
        if not p.is_file():
            return None
        try:
            data = json.loads(p.read_text())
        except (OSError, json.JSONDecodeError):
            return None
        with self._lock:
            self.hits += 1
        return data

    def put(self, key: str, result: Dict[str, Any]) -> None:
        if not self.enabled:
            return
        p = self._path(key)
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(".tmp")
            tmp.write_text(json.dumps(result, default=str))
            tmp.replace(p)  # atomic
            with self._lock:
                self.writes += 1
        except OSError:
            pass  # cache is best-effort; a write failure must never fail a run

    def stats(self) -> Dict[str, int]:
        with self._lock:
            return {"hits": self.hits, "writes": self.writes}
