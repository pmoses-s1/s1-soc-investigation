"""
Validate catalog PowerQuery bodies against SDL.

Each query is launched over a short recent window through the LRQ engine. If the
backend rejects it with a 400-class syntax error, it is invalid and the message is
returned. If it launches and completes (even with zero rows), it is valid. Transient
conditions (rate limit, server busy, timeout) return "unknown" rather than failing a
query, since they are not the query's fault.

This is the same acceptance test the engine's error classification uses at run time,
so a query that validates here will not be marked `permanent` mid-run.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from .catalog import Catalog
from .config import EngineConfig
from .lrq_client import (LRQClient, QuerySyntaxError, RateLimitError, ServerError,
                         LRQError, RequestsTransport, Transport)
from .rate_limiter import TokenBucket
from .slicing import iso_z


def _probe_vars(catalog: Catalog) -> Dict[str, str]:
    return {v: "validation_probe" for v in catalog.required_vars()}


def validate_catalog(config: EngineConfig, catalog: Catalog, *,
                     transport: Optional[Transport] = None,
                     window_hours: int = 1) -> List[Dict[str, Any]]:
    now = datetime.now(timezone.utc)
    start_iso = iso_z(now - timedelta(hours=window_hours))
    end_iso = iso_z(now)
    variables = _probe_vars(catalog)

    tp = transport or RequestsTransport(verify_tls=config.verify_tls, pool_maxsize=4)
    token = (config.tokens or ["__mock__"])[0]
    bucket = TokenBucket(rps=config.rps or 2.5, burst=config.burst or 3)
    client = LRQClient(config.console_url or "https://mock.local", token, bucket, tp,
                       name="validator", poll_interval_s=config.poll_interval_s,
                       query_timeout_s=min(30.0, config.query_timeout_s))

    # Validation = "does SDL accept and start this query?" We launch it and poll
    # briefly. A 400 rejection (unknown function, bad command) is INVALID. A query
    # that parses and starts is VALID, even if it is still running when the short
    # budget elapses (a slow query is not a broken query).
    budget = min(12.0, max(4.0, config.query_timeout_s))
    results: List[Dict[str, Any]] = []
    for q in catalog.enabled_queries():
        try:
            pq = q.render(variables)
        except KeyError as e:
            results.append({"query_id": q.id, "title": q.title, "status": "invalid",
                            "error": f"template error: {e}"})
            continue
        try:
            qid, tag = client.launch(pq, start_iso, end_iso, tenant=config.tenant,
                                     account_ids=config.account_ids or None, priority="LOW")
        except QuerySyntaxError as e:
            results.append({"query_id": q.id, "title": q.title, "status": "invalid",
                            "error": str(e)[:300]})
            continue
        except (RateLimitError, ServerError, LRQError) as e:
            results.append({"query_id": q.id, "title": q.title, "status": "unknown",
                            "error": f"could not reach SDL: {str(e)[:200]}"})
            continue

        deadline = time.monotonic() + budget
        last_seen = 0
        result = {"query_id": q.id, "title": q.title, "status": "valid",
                  "error": "accepted (still running at validation cutoff)"}
        try:
            while time.monotonic() < deadline:
                resp = client.poll(qid, tag, last_seen)
                total = int(resp.get("stepsTotal") or 0)
                done = int(resp.get("stepsCompleted") or 0)
                last_seen = done
                if total > 0 and done >= total:
                    data = resp.get("data") or {}
                    result = {"query_id": q.id, "title": q.title, "status": "valid",
                              "error": "", "rows": len(data.get("values") or []),
                              "match_count": int(data.get("matchCount")
                                                 or resp.get("matchCount") or 0)}
                    break
                time.sleep(1.0)
        except QuerySyntaxError as e:
            result = {"query_id": q.id, "title": q.title, "status": "invalid",
                      "error": str(e)[:300]}
        except (RateLimitError, ServerError, LRQError) as e:
            result = {"query_id": q.id, "title": q.title, "status": "unknown",
                      "error": str(e)[:200]}
        finally:
            client.cancel(qid, tag)
        results.append(result)
    return results
