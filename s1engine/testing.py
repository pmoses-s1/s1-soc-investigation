"""
FakeTransport: an in-memory LRQ backend for offline runs and tests.

It mimics the launch/poll/cancel wire protocol, returns synthetic tabular data,
and can inject failures so the engine's retry, throttle-backoff, subdivision,
and resume paths are exercisable without a live tenant (the sandbox blocks
egress to sentinelone.net anyway).

Failure injection is keyed on the query string so a test can make a specific
catalog query flaky or permanently broken:
  throttle_first_n   - return 429 for the first N launches globally
  fail_query_substr  - {substring: "syntax"|"server"} to force an error class
  slow_query_substr  - substrings whose slices report a wall-timeout once
"""

from __future__ import annotations

import threading
import uuid
from typing import Any, Dict, List, Optional, Tuple


class FakeTransport:
    def __init__(self, *, throttle_first_n: int = 0,
                 fail_query_substr: Optional[Dict[str, str]] = None,
                 rows_per_slice: int = 3):
        self._lock = threading.Lock()
        self._queries: Dict[str, Dict[str, Any]] = {}
        self._throttle_budget = throttle_first_n
        self._fail = fail_query_substr or {}
        self._rows = rows_per_slice
        self.launches = 0
        self.polls = 0
        self.cancels = 0
        self._timed_out_once: set = set()

    # ------------------------------------------------------------- POST
    def post(self, url: str, json_body: Dict[str, Any], headers: Dict[str, str]
             ) -> Tuple[int, Any, Dict[str, str]]:
        with self._lock:
            self.launches += 1
            if self._throttle_budget > 0:
                self._throttle_budget -= 1
                return 429, {"status": "error/server/backoff",
                             "message": "rate limited (injected)"}, {}
            pq = (json_body.get("pq") or {}).get("query", "")
            for substr, kind in self._fail.items():
                if substr in pq:
                    if kind == "syntax":
                        return 400, {"message": "Don't understand [bogus] (injected)"}, {}
                    if kind == "server":
                        return 500, {"message": "server error (injected)"}, {}
            qid = uuid.uuid4().hex[:16]
            tag = "ftag-" + uuid.uuid4().hex[:8]
            self._queries[qid] = {
                "tag": tag, "pq": pq,
                "start": json_body.get("startTime"),
                "end": json_body.get("endTime"),
                "polled": 0,
            }
            return 200, {"id": qid, "stepsCompleted": 0, "stepsTotal": 0, "data": None}, \
                {"X-Dataset-Query-Forward-Tag": tag}

    # -------------------------------------------------------------- GET
    def get(self, url: str, headers: Dict[str, str]) -> Tuple[int, Any, Dict[str, str]]:
        with self._lock:
            self.polls += 1
            qid = url.split("/sdl/v2/api/queries/")[1].split("?")[0]
            q = self._queries.get(qid)
            if q is None:
                return 404, {"message": "no such query"}, {}
            q["polled"] += 1
            # Complete on the second poll to exercise the poll loop.
            if q["polled"] < 2:
                return 200, {"stepsCompleted": 0, "stepsTotal": 2, "data": None}, {}
            cols = ["event_day", "hits", "first_seen", "last_seen"]
            vals: List[List[Any]] = []
            for i in range(self._rows):
                vals.append([q["start"], 10 + i, q["start"], q["end"]])
            return 200, {
                "stepsCompleted": 2, "stepsTotal": 2, "cpuUsage": 12.5,
                "matchCount": self._rows * 100,
                "data": {"columns": [{"name": c} for c in cols], "values": vals,
                         "matchCount": self._rows * 100},
            }, {}

    # ----------------------------------------------------------- DELETE
    def delete(self, url: str, headers: Dict[str, str]) -> Tuple[int, Any, Dict[str, str]]:
        with self._lock:
            self.cancels += 1
            qid = url.rstrip("/").split("/")[-1]
            self._queries.pop(qid, None)
            return 200, {"status": "success"}, {}
