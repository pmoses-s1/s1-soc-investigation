"""
LRQ v2 async client (launch / poll / cancel).

This is the canonical programmatic PowerQuery path:

  POST   /sdl/v2/api/queries              -> launch, returns id + forward tag
  GET    /sdl/v2/api/queries/{id}?lastStepSeen=N  -> poll
  DELETE /sdl/v2/api/queries/{id}         -> cancel (always, even on success)

Key behaviours baked in:
  * The X-Dataset-Query-Forward-Tag from the POST response header is echoed on
    every GET and DELETE; without it the router rejects the request.
  * A query expires 30s after the last poll, so we poll every ~1.5s.
  * Every API call passes through the token bucket first (polls cost budget too).
  * Errors are classified so the engine can decide retry vs subdivide vs give up:
      RateLimitError    -> 429 / server backoff  (throttle: back off + requeue)
      ServerError       -> 5xx or client-side timeout (retry, then subdivide)
      QuerySyntaxError  -> 400 bad query/command  (permanent: catalog bug)
      LRQError          -> anything else non-retryable

Transport is pluggable so the engine is fully testable offline: RequestsTransport
hits the real console, FakeTransport simulates launch/poll/cancel with synthetic
data and injectable failures.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

from .rate_limiter import TokenBucket


# --------------------------------------------------------------------- errors
class LRQError(RuntimeError):
    def __init__(self, message: str, status: Optional[int] = None, body: Any = None):
        super().__init__(message)
        self.status = status
        self.body = body


class RateLimitError(LRQError):
    """429 or SDL server backoff. Transient; back off and requeue."""


class ServerError(LRQError):
    """5xx or client-side transport error. Transient; retry then subdivide."""


class SliceTimeout(ServerError):
    """The slice exceeded its wall-clock budget before completing. This is
    deterministic for a given (query, window) size, so retrying the SAME slice at
    the SAME granularity just times out again. The engine subdivides immediately
    instead of burning its retry budget on identical attempts. Subclasses
    ServerError so any existing `except ServerError` still catches it."""


class QuerySyntaxError(LRQError):
    """400 caused by a malformed query/command. Permanent; do not retry."""


_SYNTAX_MARKERS = (
    "don't understand", "dont understand", "unknown command", "query type",
    "must be specified", "can only be used", "must be enclosed",
    "does not match any supported pattern", "is ambiguous",
)


def classify_http(status: int, body: Any) -> Optional[LRQError]:
    """Map an HTTP status + body to a typed error, or None if it is a success."""
    msg = ""
    sdl_status = None
    if isinstance(body, dict):
        msg = str(body.get("message") or body.get("errors") or "")
        sdl_status = body.get("status")
    low = msg.lower()
    if status == 429 or (isinstance(sdl_status, str) and sdl_status.startswith("error/server/backoff")):
        return RateLimitError(msg or "rate limited", status, body)
    if 500 <= status < 600:
        return ServerError(msg or f"server error {status}", status, body)
    if status == 400:
        # A 400 is a client-side rejection of the query/params (unknown function,
        # bad command, wrong scope). It is never transient, so treat every 400 as
        # a permanent query error. _SYNTAX_MARKERS is kept for message context.
        return QuerySyntaxError(msg or "bad request (400)", status, body)
    if status >= 400:
        return LRQError(msg or f"http {status}", status, body)
    return None


# ------------------------------------------------------------------ transport
class Transport(Protocol):
    def post(self, url: str, json_body: Dict[str, Any], headers: Dict[str, str]
             ) -> Tuple[int, Any, Dict[str, str]]: ...
    def get(self, url: str, headers: Dict[str, str]) -> Tuple[int, Any, Dict[str, str]]: ...
    def delete(self, url: str, headers: Dict[str, str]) -> Tuple[int, Any, Dict[str, str]]: ...


class RequestsTransport:
    """Real HTTP transport backed by requests, with a sized connection pool."""

    def __init__(self, verify_tls: bool = True, timeout: float = 30.0, pool_maxsize: int = 12):
        import requests
        from requests.adapters import HTTPAdapter
        self._session = requests.Session()
        adapter = HTTPAdapter(pool_maxsize=pool_maxsize, pool_connections=pool_maxsize)
        self._session.mount("https://", adapter)
        self._verify = verify_tls
        self._timeout = timeout

    def _do(self, method: str, url: str, headers: Dict[str, str],
            json_body: Optional[Dict[str, Any]] = None) -> Tuple[int, Any, Dict[str, str]]:
        import requests
        try:
            resp = self._session.request(method, url, headers=headers,
                                         json=json_body, verify=self._verify,
                                         timeout=self._timeout)
        except requests.exceptions.Timeout as exc:
            raise ServerError(f"client timeout: {exc}") from exc
        except requests.exceptions.RequestException as exc:
            raise ServerError(f"transport error: {exc}") from exc
        try:
            body = resp.json() if resp.content else {}
        except ValueError:
            body = {"_raw": resp.text}
        return resp.status_code, body, dict(resp.headers)

    def post(self, url, json_body, headers):
        return self._do("POST", url, headers, json_body)

    def get(self, url, headers):
        return self._do("GET", url, headers)

    def delete(self, url, headers):
        return self._do("DELETE", url, headers)


# --------------------------------------------------------------------- result
@dataclass
class QueryResult:
    columns: List[str]
    values: List[List[Any]]
    match_count: int
    row_count: int
    cpu_ms: float
    elapsed_s: float
    lrq_id: str
    polls: int


# --------------------------------------------------------------------- client
class LRQClient:
    """One client per service-user token. Owns its own rate bucket."""

    def __init__(self, console_url: str, token: str, bucket: TokenBucket,
                 transport: Transport, *, name: str = "",
                 poll_interval_s: float = 1.5, query_timeout_s: float = 120.0):
        self.base = console_url.rstrip("/")
        self.token = token
        self.bucket = bucket
        self.transport = transport
        self.name = name or f"client-{id(self) & 0xffff:x}"
        self.poll_interval_s = poll_interval_s
        self.query_timeout_s = query_timeout_s

    def _headers(self, forward_tag: Optional[str] = None) -> Dict[str, str]:
        h = {"Authorization": f"Bearer {self.token}", "Accept": "application/json"}
        if forward_tag:
            h["X-Dataset-Query-Forward-Tag"] = forward_tag
        return h

    def launch(self, pq: str, start_iso: str, end_iso: str, *, tenant: bool = True,
               account_ids: Optional[List[str]] = None, priority: str = "LOW"
               ) -> Tuple[str, str]:
        body: Dict[str, Any] = {
            "queryType": "PQ",
            "startTime": start_iso,
            "endTime": end_iso,
            "queryPriority": priority,
            "pq": {"query": pq, "resultType": "TABLE"},
        }
        if account_ids:
            body["tenant"] = False
            body["accountIds"] = account_ids
        else:
            body["tenant"] = tenant
        self.bucket.acquire()
        status, resp, headers = self.transport.post(
            f"{self.base}/sdl/v2/api/queries", body, self._headers())
        err = classify_http(status, resp)
        if err:
            raise err
        qid = resp.get("id")
        # Header lookup is case-insensitive in requests; be defensive for fakes.
        tag = headers.get("X-Dataset-Query-Forward-Tag") or headers.get("x-dataset-query-forward-tag")
        if not qid or not tag:
            raise LRQError(f"launch missing id/forward-tag (id={qid!r} tag={tag!r})",
                           status, resp)
        return qid, tag

    def poll(self, qid: str, forward_tag: str, last_seen: int) -> Dict[str, Any]:
        self.bucket.acquire()
        url = f"{self.base}/sdl/v2/api/queries/{qid}?lastStepSeen={last_seen}"
        status, resp, _ = self.transport.get(url, self._headers(forward_tag))
        err = classify_http(status, resp)
        if err:
            raise err
        return resp

    def cancel(self, qid: str, forward_tag: str) -> None:
        try:
            self.bucket.acquire()
            self.transport.delete(f"{self.base}/sdl/v2/api/queries/{qid}",
                                  self._headers(forward_tag))
        except LRQError:
            pass  # best-effort cleanup

    def run_pq(self, pq: str, start_iso: str, end_iso: str, *, tenant: bool = True,
               account_ids: Optional[List[str]] = None, priority: str = "LOW"
               ) -> QueryResult:
        """Full launch -> poll -> collect -> cancel lifecycle for one slice."""
        t0 = time.monotonic()
        qid, tag = self.launch(pq, start_iso, end_iso, tenant=tenant,
                               account_ids=account_ids, priority=priority)
        polls = 0
        last_seen = 0
        try:
            while True:
                if time.monotonic() - t0 > self.query_timeout_s:
                    raise SliceTimeout(f"slice exceeded {self.query_timeout_s}s wall timeout")
                resp = self.poll(qid, tag, last_seen)
                polls += 1
                steps_total = int(resp.get("stepsTotal") or 0)
                steps_done = int(resp.get("stepsCompleted") or 0)
                last_seen = steps_done
                if steps_total > 0 and steps_done >= steps_total:
                    data = resp.get("data") or {}
                    columns = [c.get("name") if isinstance(c, dict) else c
                               for c in (data.get("columns") or [])]
                    values = data.get("values") or []
                    return QueryResult(
                        columns=columns,
                        values=values,
                        match_count=int(data.get("matchCount") or resp.get("matchCount") or 0),
                        row_count=len(values),
                        cpu_ms=float(resp.get("cpuUsage") or 0.0),
                        elapsed_s=time.monotonic() - t0,
                        lrq_id=qid,
                        polls=polls,
                    )
                time.sleep(self.poll_interval_s)
        finally:
            self.cancel(qid, tag)
