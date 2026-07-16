#!/usr/bin/env python3
"""
s1-soc-investigation, local web UI + run server.

Zero-dependency (stdlib http.server) local web app that drives the investigation
engine. It follows the same hardening posture as s1-ueba-deployer:

  * Credentials live server-side only. The browser never receives a token; the
    UI only sees presence/redacted flags. Every SDL call is made by the engine
    inside this process.
  * Binds to 127.0.0.1 by default. To expose it on a network you must set
    S1IE_BIND_ALL=1 AND a strong S1IE_AUTH_TOKEN; the server refuses to start
    exposed without a token and enforces it on every /api call.
  * Cross-origin POSTs are rejected unless from localhost or an allowlisted
    origin.

Run locally:
  export S1_CONSOLE_URL=...  S1_LRQ_TOKENS=tok1,tok2
  python app/server.py            # then open http://localhost:8801

Everything the engine produces (ledger, activity.jsonl, per-slice cache, merged
results, manifest) is written under the output folder the user picks in the UI
(S1IE_OUTPUT_DIR sets the default / container mount point).
"""

from __future__ import annotations

import json
import os
import sys
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
sys.path.insert(0, str(REPO))

from s1engine.activity import ActivityLog                     # noqa: E402
from s1engine.catalog import load_catalog                     # noqa: E402
from s1engine.config import EngineConfig, load_config         # noqa: E402
from s1engine.engine import InvestigationEngine, RunParams    # noqa: E402
from s1engine.ledger import Ledger                            # noqa: E402
from s1engine.verify import verify_run                        # noqa: E402

PORT = int(os.environ.get("S1IE_PORT", "8801"))
HOST = os.environ.get("S1IE_HOST", "127.0.0.1")
OUTPUT_BASE = Path(os.environ.get("S1IE_OUTPUT_DIR", str(REPO / "investigations")))
CATALOG_DIR = Path(os.environ.get("S1IE_CATALOG_DIR", str(REPO / "catalogs")))
AUTH_TOKEN = os.environ.get("S1IE_AUTH_TOKEN", "").strip()
EXPOSED = os.environ.get("S1IE_BIND_ALL", "").strip().lower() in ("1", "true", "yes", "on")
_EXTRA_ORIGINS = {o.strip() for o in os.environ.get("S1IE_ALLOWED_ORIGINS", "").split(",") if o.strip()}

# In-memory credential store. Never persisted to disk, never sent to the browser.
_CREDS: dict = {}
_CREDS_LOCK = threading.Lock()

# Run registry: run_id -> dict(status, activity, verification, stats, run_dir, ...)
_RUNS: dict = {}
_RUNS_LOCK = threading.Lock()


# --------------------------------------------------------------------- security
def _origin_ok(origin: str | None) -> bool:
    if origin in _EXTRA_ORIGINS:
        return True
    if not origin:
        return not EXPOSED
    return urlparse(origin).hostname in ("localhost", "127.0.0.1")


def _auth_ok(handler: "H") -> bool:
    if AUTH_TOKEN:
        hdr = handler.headers.get("X-Auth-Token", "")
        if hdr:
            return hdr == AUTH_TOKEN
        qs = parse_qs(urlparse(handler.path).query)
        return qs.get("token", [""])[0] == AUTH_TOKEN
    return not EXPOSED


# ------------------------------------------------------------------- helpers
def _effective_creds() -> dict:
    """Env vars provide defaults; the in-UI Connect panel overrides them."""
    with _CREDS_LOCK:
        return dict(_CREDS)


def build_config(mock: bool, mock_tokens: int = 2) -> EngineConfig:
    creds = _effective_creds()
    if mock:
        return load_config(require_credentials=False, console_url="https://mock.local",
                           tokens=[f"mock-tok-{i+1}" for i in range(max(1, mock_tokens))],
                           rps=1000.0)
    overrides = {}
    if creds.get("console_url"):
        overrides["console_url"] = creds["console_url"]
    if creds.get("tokens"):
        overrides["tokens"] = creds["tokens"]
    if creds.get("rps"):
        overrides["rps"] = float(creds["rps"])
    if creds.get("account_ids"):
        overrides["account_ids"] = creds["account_ids"]
    return load_config(**overrides)


def creds_status() -> dict:
    creds = _effective_creds()
    # Fall back to env for presence display.
    console = creds.get("console_url") or os.environ.get("S1_CONSOLE_URL", "")
    n_tokens = len(creds.get("tokens") or [])
    if not n_tokens:
        env_tokens = os.environ.get("S1_LRQ_TOKENS") or os.environ.get("S1_CONSOLE_API_TOKEN") or ""
        n_tokens = len([t for t in env_tokens.split(",") if t.strip()])
    return {
        "console_url": console,
        "num_tokens": n_tokens,
        "creds_ok": bool(console and n_tokens),
        "account_ids": creds.get("account_ids") or [],
        "rps": creds.get("rps") or float(os.environ.get("S1_LRQ_RPS", "2.5")),
    }


def list_catalogs() -> list:
    out = []
    if CATALOG_DIR.is_dir():
        for p in sorted(CATALOG_DIR.glob("*.y*ml")) + sorted(CATALOG_DIR.glob("*.json")):
            try:
                cat = load_catalog(p)
                out.append({"path": str(p), "name": cat.name,
                            "queries": len(cat.enabled_queries()),
                            "vars": cat.required_vars()})
            except Exception as e:
                out.append({"path": str(p), "name": p.name, "error": str(e)})
    return out


def _resolve_output_dir(raw: str | None) -> Path:
    raw = (raw or "").strip()
    if not raw:
        return OUTPUT_BASE
    p = Path(raw)
    return p if p.is_absolute() else (OUTPUT_BASE / p)


def start_run(d: dict) -> dict:
    case = (d.get("case") or "case").strip()
    entity = (d.get("entity") or "").strip()
    if not entity:
        raise ValueError("entity is required")
    catalog_path = d.get("catalog")
    if not catalog_path:
        raise ValueError("catalog is required")
    catalog = load_catalog(catalog_path)

    mock = bool(d.get("mock"))
    config = build_config(mock, int(d.get("mockTokens", 2)))
    run_id = d.get("runId") or f"{case}-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}"
    out_base = _resolve_output_dir(d.get("outputDir"))
    run_dir = out_base / _safe(case) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)

    transport = None
    if mock:
        from s1engine.testing import FakeTransport
        transport = FakeTransport(throttle_first_n=int(d.get("mockThrottle", 0)))

    ledger = Ledger(run_dir / "ledger.db")
    activity = ActivityLog(run_dir / "activity.jsonl")
    engine = InvestigationEngine(config, output_root=run_dir, transport=transport,
                                 pool_size=d.get("pool"), activity=activity)
    params = RunParams(
        case_id=case, entity=entity, lookback_days=int(d.get("lookback", 90)),
        slice_days=int(d.get("sliceDays", 1)), max_attempts=int(d.get("maxAttempts", 4)),
        subdivide_on_timeout=bool(d.get("subdivide", True)),
        priority=d.get("priority", "LOW"), variables=d.get("vars") or {})

    reg = {"run_id": run_id, "case": case, "entity": entity, "run_dir": str(run_dir),
           "catalog": catalog.name, "status": "running", "activity": activity,
           "verification": None, "stats": None, "error": None,
           "started_at": datetime.now(timezone.utc).isoformat()}
    with _RUNS_LOCK:
        _RUNS[run_id] = reg

    def worker():
        try:
            engine.plan(run_id, catalog, params, ledger)
            result = engine.run(run_id, ledger, params)
            manifest = engine.finalize(run_id, ledger, catalog, params)
            result_rows = {q["query_id"]: q["result_rows"] for q in manifest["queries"]}
            v = verify_run(ledger, run_id, catalog, result_rows=result_rows)
            reg["stats"] = result["stats"]
            reg["verification"] = v.to_dict()
            reg["manifest"] = manifest
            reg["status"] = "complete" if v.passed else "incomplete"
            activity.log({"event": "verification", "passed": v.passed,
                          "passed_queries": v.passed_queries,
                          "total_queries": v.total_queries})
        except Exception as e:  # noqa: BLE001 - surface any failure to the UI
            reg["status"] = "error"
            reg["error"] = str(e)
            try:
                activity.log({"event": "error", "error": str(e)})
            except Exception:
                pass
        finally:
            try:
                ledger.close()
            except Exception:
                pass

    threading.Thread(target=worker, name=f"run-{run_id}", daemon=True).start()
    return {"run_id": run_id, "run_dir": str(run_dir)}


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in str(name))


# ------------------------------------------------------------------- handler
class H(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json", headers=None):
        if not isinstance(body, (bytes, bytearray)):
            body = json.dumps(body, default=str).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        p = self.path.split("?")[0]
        if p in ("/", "/index.html"):
            try:
                return self._send(200, (HERE / "index.html").read_bytes(),
                                  "text/html; charset=utf-8")
            except Exception as e:
                return self._send(500, f"cannot read index.html: {e}", "text/plain")
        if p.startswith("/api/") and not _auth_ok(self):
            return self._send(401, {"error": "authentication required: pass ?token= or X-Auth-Token"})
        qs = parse_qs(urlparse(self.path).query)
        if p == "/api/config":
            return self._send(200, {**creds_status(), "catalogs": list_catalogs(),
                                    "output_base": str(OUTPUT_BASE),
                                    "exposed": EXPOSED})
        if p == "/api/runs":
            with _RUNS_LOCK:
                runs = [{"run_id": r["run_id"], "case": r["case"], "entity": r["entity"],
                         "status": r["status"], "started_at": r.get("started_at")}
                        for r in _RUNS.values()]
            return self._send(200, {"runs": runs})
        if p == "/api/activity":
            run_id = qs.get("runId", [""])[0]
            since = int(qs.get("since", ["0"])[0])
            reg = _RUNS.get(run_id)
            if not reg:
                return self._send(404, {"error": "unknown run"})
            events = reg["activity"].tail(since)
            return self._send(200, {"events": events, "last_seq": reg["activity"].last_seq(),
                                    "status": reg["status"]})
        if p == "/api/status":
            run_id = qs.get("runId", [""])[0]
            reg = _RUNS.get(run_id)
            if not reg:
                return self._send(404, {"error": "unknown run"})
            return self._send(200, {"status": reg["status"], "stats": reg.get("stats"),
                                    "error": reg.get("error"),
                                    "verification": reg.get("verification"),
                                    "run_dir": reg["run_dir"]})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if not _auth_ok(self):
            return self._send(401, {"error": "authentication required"})
        if not _origin_ok(self.headers.get("Origin")):
            return self._send(403, {"error": "cross-origin request rejected"})
        n = int(self.headers.get("Content-Length", 0) or 0)
        try:
            d = json.loads(self.rfile.read(n) or b"{}") if n else {}
        except Exception:
            d = {}
        p = self.path.split("?")[0]
        try:
            if p == "/api/connect":
                tokens = d.get("tokens")
                if isinstance(tokens, str):
                    tokens = [t.strip() for t in tokens.replace("\n", ",").split(",") if t.strip()]
                acct = d.get("account_ids")
                if isinstance(acct, str):
                    acct = [a.strip() for a in acct.split(",") if a.strip()]
                with _CREDS_LOCK:
                    if d.get("console_url"):
                        _CREDS["console_url"] = d["console_url"].rstrip("/")
                    if tokens:
                        _CREDS["tokens"] = tokens
                    if d.get("rps"):
                        _CREDS["rps"] = d["rps"]
                    _CREDS["account_ids"] = acct or []
                return self._send(200, creds_status())
            if p == "/api/run":
                return self._send(200, start_run(d))
            return self._send(404, {"error": "unknown endpoint"})
        except Exception as e:  # noqa: BLE001
            return self._send(400, {"error": str(e)})

    def log_message(self, *a):
        pass


def main() -> int:
    if EXPOSED and not AUTH_TOKEN:
        sys.stderr.write(
            "REFUSING TO START: S1IE_BIND_ALL is set (network exposure) but "
            "S1IE_AUTH_TOKEN is empty.\nSet S1IE_AUTH_TOKEN=<strong-secret> and open "
            "the UI at ?token=<secret>, or unset S1IE_BIND_ALL and publish to the host "
            "loopback only (docker run -p 127.0.0.1:8901:8801 ...).\n")
        return 2
    OUTPUT_BASE.mkdir(parents=True, exist_ok=True)
    st = creds_status()
    print(f"s1-soc-investigation  ->  http://localhost:{PORT}")
    print(f"console               ->  {st['console_url'] or '(S1_CONSOLE_URL not set; use the Connect panel)'}")
    print(f"tokens                ->  {st['num_tokens']} configured")
    print(f"output base           ->  {OUTPUT_BASE}")
    if AUTH_TOKEN:
        print("auth                  ->  token required (?token= or X-Auth-Token)")
    if EXPOSED:
        print(f"exposure              ->  bound to {HOST} (network-reachable); token enforced")
    elif HOST not in ("127.0.0.1", "localhost", "::1"):
        print(f"WARNING               ->  bound to {HOST} without S1IE_BIND_ALL; for network use set "
              "S1IE_BIND_ALL=1 + S1IE_AUTH_TOKEN or publish to 127.0.0.1 only.")
    print("Ctrl-C to stop.")
    httpd = ThreadingHTTPServer((HOST, PORT), H)
    httpd.daemon_threads = True
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
