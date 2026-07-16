"""
Configuration and credential resolution for the investigation engine.

The LRQ v2 API needs two things: the tenant's own console host (for example
https://your-tenant.sentinelone.net, NOT xdr.us1.sentinelone.net) and one or
more console service-user JWTs. Multiple JWTs (distinct `sub` claims) let the
engine round-robin slices to multiply the per-user rate budget.

Resolution order (later wins):
  1. A credentials.json in the engine dir, the cwd, or $COWORK_WORKSPACE.
  2. Environment variables.
  3. Explicit keyword overrides passed to load_config().

Recognised keys (env var == JSON key):
  S1_CONSOLE_URL       Console host for LRQ, e.g. https://your-tenant.sentinelone.net
  S1_LRQ_TOKENS        Comma-separated list of service-user JWTs (round-robin)
  S1_CONSOLE_API_TOKEN Single JWT (used if S1_LRQ_TOKENS is absent)
  S1_LRQ_RPS           Per-token token-bucket rate (default 2.5)
  S1_LRQ_ACCOUNT_IDS   Comma-separated account IDs (pairs with tenant=false)
  SDL_VERIFY_TLS       "false" to disable TLS verification (default true)

SDL_XDR_URL is accepted only to warn: it is the V1 endpoint and is the wrong
host for LRQ.
"""

from __future__ import annotations

import json
import os
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional


_CRED_FILENAMES = ("credentials.json",)


def _candidate_cred_paths() -> List[Path]:
    paths: List[Path] = []
    here = Path(__file__).resolve().parent.parent  # repo root
    paths.append(here / "credentials.json")
    ws = os.environ.get("COWORK_WORKSPACE", "").strip()
    if ws:
        paths.append(Path(ws) / "credentials.json")
    try:
        cwd = Path.cwd()
        for i, parent in enumerate([cwd, *cwd.parents]):
            if i >= 6:
                break
            paths.append(parent / "credentials.json")
    except OSError:
        pass
    # De-dup while preserving order.
    seen, out = set(), []
    for p in paths:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


def _read_cred_files() -> Dict[str, Any]:
    merged: Dict[str, Any] = {}
    for p in _candidate_cred_paths():
        if p.is_file():
            try:
                merged.update(json.loads(p.read_text()))
            except (OSError, json.JSONDecodeError):
                continue
    return merged


def _as_list(val: Any) -> List[str]:
    if val is None:
        return []
    if isinstance(val, list):
        return [str(v).strip() for v in val if str(v).strip()]
    return [s.strip() for s in str(val).split(",") if s.strip()]


@dataclass
class EngineConfig:
    console_url: str
    tokens: List[str]
    rps: float = 2.5
    burst: int = 3
    account_ids: List[str] = field(default_factory=list)
    tenant: bool = True
    verify_tls: bool = True
    query_timeout_s: float = 120.0
    poll_interval_s: float = 1.5

    @property
    def num_tokens(self) -> int:
        return len(self.tokens)

    def redacted(self) -> Dict[str, Any]:
        return {
            "console_url": self.console_url,
            "num_tokens": self.num_tokens,
            "rps": self.rps,
            "burst": self.burst,
            "account_ids": self.account_ids,
            "tenant": self.tenant,
            "verify_tls": self.verify_tls,
            "query_timeout_s": self.query_timeout_s,
            "poll_interval_s": self.poll_interval_s,
        }


def load_config(require_credentials: bool = True, **overrides: Any) -> EngineConfig:
    """Resolve engine config from files, env, and overrides.

    Set require_credentials=False for offline/mock runs that never touch the
    network (the CLI --mock path does this).
    """
    src: Dict[str, Any] = {}
    src.update(_read_cred_files())
    for key in (
        "S1_CONSOLE_URL", "S1_LRQ_TOKENS", "S1_CONSOLE_API_TOKEN",
        "S1_API_TOKEN", "S1_LRQ_RPS", "S1_LRQ_ACCOUNT_IDS",
        "SDL_VERIFY_TLS", "SDL_XDR_URL",
    ):
        if os.environ.get(key):
            src[key] = os.environ[key]

    console_url = overrides.get("console_url") or src.get("S1_CONSOLE_URL") or ""
    console_url = str(console_url).rstrip("/")
    if not console_url and src.get("SDL_XDR_URL"):
        warnings.warn(
            "Only SDL_XDR_URL is set. That is the V1 SDL endpoint and is the "
            "wrong host for the LRQ v2 API. Set S1_CONSOLE_URL to your tenant "
            "console host (https://your-tenant.sentinelone.net).",
            RuntimeWarning,
        )

    tokens = overrides.get("tokens")
    if tokens is None:
        tokens = _as_list(src.get("S1_LRQ_TOKENS"))
        if not tokens:
            single = src.get("S1_CONSOLE_API_TOKEN") or src.get("S1_API_TOKEN")
            if single:
                tokens = [str(single).strip()]
    tokens = list(tokens or [])

    rps = float(overrides.get("rps") or src.get("S1_LRQ_RPS") or 2.5)
    account_ids = overrides.get("account_ids")
    if account_ids is None:
        account_ids = _as_list(src.get("S1_LRQ_ACCOUNT_IDS"))
    tenant = overrides.get("tenant")
    if tenant is None:
        tenant = not account_ids  # explicit accounts imply tenant=false

    verify = overrides.get("verify_tls")
    if verify is None:
        v = src.get("SDL_VERIFY_TLS")
        verify = True if v is None else str(v).lower() not in ("0", "false", "no")

    if require_credentials:
        if not console_url:
            raise RuntimeError(
                "S1_CONSOLE_URL is not set. Point it at your tenant console "
                "host, e.g. https://your-tenant.sentinelone.net"
            )
        if not tokens:
            raise RuntimeError(
                "No service-user JWTs found. Set S1_LRQ_TOKENS (comma-separated "
                "for round-robin) or S1_CONSOLE_API_TOKEN."
            )

    return EngineConfig(
        console_url=console_url,
        tokens=tokens,
        rps=rps,
        burst=int(overrides.get("burst") or max(3, round(rps))),
        account_ids=account_ids,
        tenant=bool(tenant),
        verify_tls=bool(verify),
        query_timeout_s=float(overrides.get("query_timeout_s") or 120.0),
        poll_interval_s=float(overrides.get("poll_interval_s") or 1.5),
    )
