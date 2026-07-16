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

    results: List[Dict[str, Any]] = []
    for q in catalog.enabled_queries():
        try:
            pq = q.render(variables)
        except KeyError as e:
            results.append({"query_id": q.id, "title": q.title, "status": "invalid",
                            "error": f"template error: {e}"})
            continue
        try:
            res = client.run_pq(pq, start_iso, end_iso,
                                tenant=config.tenant,
                                account_ids=config.account_ids or None, priority="LOW")
            results.append({"query_id": q.id, "title": q.title, "status": "valid",
                            "error": "", "rows": res.row_count,
                            "match_count": res.match_count})
        except QuerySyntaxError as e:
            results.append({"query_id": q.id, "title": q.title, "status": "invalid",
                            "error": str(e)[:300]})
        except (RateLimitError, ServerError) as e:
            results.append({"query_id": q.id, "title": q.title, "status": "unknown",
                            "error": f"transient, could not validate now: {str(e)[:200]}"})
        except LRQError as e:
            results.append({"query_id": q.id, "title": q.title, "status": "unknown",
                            "error": str(e)[:200]})
    return results
