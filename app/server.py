#!/usr/bin/env python3
"""
s1-soc-investigation, local web UI + run server.

Zero-dependency (stdlib http.server) local web app that drives the investigation
engine, following the s1-ueba-deployer hardening posture:

  * Credentials live server-side only. The browser never receives a token; the UI
    only sees presence/redacted flags. Every SDL call is made by the engine here.
  * Binds to 127.0.0.1 by default. Network exposure requires S1IE_BIND_ALL=1 AND a
    strong S1IE_AUTH_TOKEN; the server refuses to start exposed without a token and
    enforces it on every /api call.
  * Cross-origin POSTs are rejected unless from localhost or an allowlisted origin.

Outputs (ledger, activity.jsonl, slice cache, merged results, manifest, workbook)
are written under the output folder the user picks (S1IE_OUTPUT_DIR is the default
and, in Docker, the mount point).
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

from s1engine import __version__ as ENGINE_VERSION           # noqa: E402
from s1engine.activity import ActivityLog                     # noqa: E402
from s1engine.catalog import load_catalog                     # noqa: E402
from s1engine.config import EngineConfig, load_config         # noqa: E402
from s1engine.engine import InvestigationEngine, RunParams    # noqa: E402
from s1engine.export import zip_run                           # noqa: E402
from s1engine.ledger import Ledger                            # noqa: E402
from s1engine.validate import validate_catalog                # noqa: E402
from s1engine.verify import verify_run                        # noqa: E402

PORT = int(os.environ.get("S1IE_PORT", "8801"))
HOST = os.environ.get("S1IE_HOST", "127.0.0.1")
OUTPUT_BASE = Path(os.environ.get("S1IE_OUTPUT_DIR", str(REPO / "investigations")))
BUNDLED_CATALOGS = Path(os.environ.get("S1IE_CATALOG_DIR", str(REPO / "catalogs")))
USER_CATALOGS = OUTPUT_BASE / "catalogs"   # writable, persists on the output volume
# Catalogs can be refreshed from the repo at runtime, so updating queries does not
# require rebuilding the image. Pulled files land in the persisted user catalogs dir.
CATALOG_REPO = os.environ.get("S1IE_CATALOG_REPO", "pmoses-s1/s1-soc-investigation")
CATALOG_REPO_PATH = os.environ.get("S1IE_CATALOG_REPO_PATH", "catalogs")
CATALOG_REPO_REF = os.environ.get("S1IE_CATALOG_REPO_REF", "main")
# Config datatable placeholders (the {{dt_*}} template vars). Shown as dedicated
# fields in the Variables modal; the default is the table name in the source workbook.
DATATABLES = [
    {"var": "dt_costcenters", "default": "CostCenters", "label": "Cost centers / HR"},
    {"var": "dt_accounts_intune", "default": "Accounts_intune", "label": "Intune devices"},
    {"var": "dt_accounts_jamf", "default": "Accounts_Jamf", "label": "Jamf devices"},
    {"var": "dt_accounts_github", "default": "Accounts_Github", "label": "GitHub accounts"},
    {"var": "dt_accounts_google", "default": "Accounts_Google", "label": "Google accounts"},
    {"var": "dt_jumpcloud_user_summary", "default": "jumpcloud_user_summary", "label": "JumpCloud users"},
    {"var": "dt_monitored_users_enriched", "default": "monitored_users_enriched", "label": "Monitored users (enriched)"},
    {"var": "dt_monitored_users_test", "default": "monitored_users_test", "label": "Monitored users (test)"},
]
AUTH_TOKEN = os.environ.get("S1IE_AUTH_TOKEN", "").strip()
EXPOSED = os.environ.get("S1IE_BIND_ALL", "").strip().lower() in ("1", "true", "yes", "on")
_EXTRA_ORIGINS = {o.strip() for o in os.environ.get("S1IE_ALLOWED_ORIGINS", "").split(",") if o.strip()}

_CREDS: dict = {}
_CREDS_LOCK = threading.Lock()
_RUNS: dict = {}
_RUNS_LOCK = threading.Lock()


# --------------------------------------------------------------------- security
def _origin_ok(origin):
    if origin in _EXTRA_ORIGINS:
        return True
    if not origin:
        return not EXPOSED
    return urlparse(origin).hostname in ("localhost", "127.0.0.1")


def _auth_ok(handler):
    if AUTH_TOKEN:
        hdr = handler.headers.get("X-Auth-Token", "")
        if hdr:
            return hdr == AUTH_TOKEN
        qs = parse_qs(urlparse(handler.path).query)
        return qs.get("token", [""])[0] == AUTH_TOKEN
    return not EXPOSED


def _within(path: Path, roots) -> bool:
    try:
        rp = path.resolve()
    except OSError:
        return False
    for root in roots:
        try:
            rp.relative_to(Path(root).resolve())
            return True
        except ValueError:
            continue
    return False


# ------------------------------------------------------------------- helpers
def _effective_creds() -> dict:
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
    console = creds.get("console_url") or os.environ.get("S1_CONSOLE_URL", "")
    n_tokens = len(creds.get("tokens") or [])
    if not n_tokens:
        env_tokens = os.environ.get("S1_LRQ_TOKENS") or os.environ.get("S1_CONSOLE_API_TOKEN") or ""
        n_tokens = len([t for t in env_tokens.split(",") if t.strip()])
    return {"console_url": console, "num_tokens": n_tokens,
            "creds_ok": bool(console and n_tokens),
            "account_ids": creds.get("account_ids") or [],
            "rps": creds.get("rps") or float(os.environ.get("S1_LRQ_RPS", "2.5"))}


def list_catalogs() -> list:
    out = []
    seen = set()
    for base, editable in ((USER_CATALOGS, True), (BUNDLED_CATALOGS, False)):
        if not base.is_dir():
            continue
        for p in sorted(base.glob("*.y*ml")) + sorted(base.glob("*.json")):
            if p.name in seen:
                continue
            seen.add(p.name)
            try:
                cat = load_catalog(p)
                out.append({"path": str(p), "name": cat.name, "file": p.name,
                            "queries": len(cat.enabled_queries()),
                            "vars": cat.required_vars(), "editable": editable})
            except Exception as e:
                out.append({"path": str(p), "name": p.name, "file": p.name,
                            "error": str(e), "editable": editable})
    return out


def _catalog_roots():
    return [BUNDLED_CATALOGS, USER_CATALOGS]


def _resolve_output_dir(raw):
    raw = (raw or "").strip()
    if not raw:
        return OUTPUT_BASE
    p = Path(raw)
    return p if p.is_absolute() else (OUTPUT_BASE / p)


def find_run_dir(run_id: str):
    reg = _RUNS.get(run_id)
    if reg:
        return Path(reg["run_dir"])
    if OUTPUT_BASE.is_dir():
        for case_dir in OUTPUT_BASE.iterdir():
            cand = case_dir / run_id
            if (cand / "ledger.db").is_file():
                return cand
    return None


def _safe(name: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in str(name))


def start_run(d: dict) -> dict:
    case = (d.get("case") or "case").strip()
    entity = (d.get("entity") or "").strip()
    if not entity:
        raise ValueError("entity is required")
    catalog_path = d.get("catalog")
    if not catalog_path:
        raise ValueError("catalog is required")
    catalog = load_catalog(catalog_path)
    qids = d.get("queryIds")
    if isinstance(qids, list) and qids:
        keep = set(qids)
        catalog.queries = [q for q in catalog.queries if q.id in keep]

    mock = bool(d.get("mock"))
    config = build_config(mock, int(d.get("mockTokens", 2)))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    run_id = d.get("runId") or f"{case}-{_safe(entity)[:24]}-{stamp}"
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
                                 pool_size=d.get("pool"), activity=activity,
                                 cache_dir=out_base / ".slice_cache",
                                 use_cache=bool(d.get("useCache", True)))
    params = RunParams(
        case_id=case, entity=entity, lookback_days=int(d.get("lookback", 90) or 90),
        slice_days=int(d.get("sliceDays", 1)), max_attempts=int(d.get("maxAttempts", 4)),
        subdivide_on_timeout=bool(d.get("subdivide", True)),
        priority=d.get("priority", "LOW"), variables=d.get("vars") or {},
        start_date=(d.get("startDate") or None), end_date=(d.get("endDate") or None))

    started_at = datetime.now(timezone.utc).isoformat()
    # Persist run metadata so the run can be resumed or reopened later (survives restart).
    try:
        (run_dir / "run_meta.json").write_text(json.dumps({
            "run_id": run_id, "case": case, "entity": entity, "catalog": catalog_path,
            "catalog_name": catalog.name, "lookback": d.get("lookback"),
            "sliceDays": d.get("sliceDays"), "startDate": d.get("startDate"),
            "endDate": d.get("endDate"), "vars": d.get("vars") or {},
            "queryIds": qids if (isinstance(qids, list) and qids) else None,
            "outputDir": d.get("outputDir") or "", "started_at": started_at}, indent=2))
    except Exception:
        pass
    reg = {"run_id": run_id, "case": case, "entity": entity, "run_dir": str(run_dir),
           "catalog": catalog.name, "status": "running", "activity": activity,
           "engine": engine, "ledger": ledger, "final_coverage": None,
           "verification": None, "stats": None, "workbook": None,
           "error": None, "started_at": started_at}
    with _RUNS_LOCK:
        _RUNS[run_id] = reg

    def worker():
        try:
            engine.plan(run_id, catalog, params, ledger)
            result = engine.run(run_id, ledger, params)
            manifest = engine.finalize(run_id, ledger, catalog, params)
            result_rows = {q["query_id"]: q["result_rows"] for q in manifest["queries"]}
            v = verify_run(ledger, run_id, catalog, result_rows=result_rows)
            reg["workbook"] = engine.write_workbook(run_id, manifest, v.to_dict(), params)
            reg["stats"] = result["stats"]
            reg["cache"] = result.get("cache")
            reg["verification"] = v.to_dict()
            reg["manifest"] = manifest
            if result.get("cancelled"):
                reg["status"] = "cancelled"
            else:
                reg["status"] = "complete" if v.passed else "incomplete"
            reg["final_coverage"] = result.get("coverage")
            try:
                (run_dir / "verification.json").write_text(json.dumps(v.to_dict()))
                (run_dir / "run_status.json").write_text(json.dumps({
                    "status": reg["status"], "stats": result["stats"],
                    "cache": result.get("cache"), "coverage": result.get("coverage"),
                    "workbook": reg["workbook"], "entity": entity, "catalog": catalog.name}))
            except Exception:
                pass
            activity.log({"event": "verification", "passed": v.passed,
                          "passed_queries": v.passed_queries,
                          "total_queries": v.total_queries})
        except Exception as e:  # noqa: BLE001
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


def refresh_catalogs_from_repo() -> dict:
    """Pull the catalogs/ folder from the GitHub repo into the persisted user
    catalogs dir. Lets query updates land without rebuilding the image."""
    import urllib.request
    api = f"https://api.github.com/repos/{CATALOG_REPO}/contents/{CATALOG_REPO_PATH}?ref={CATALOG_REPO_REF}"
    hdrs = {"Accept": "application/vnd.github+json", "User-Agent": "s1-soc-investigation"}
    with urllib.request.urlopen(urllib.request.Request(api, headers=hdrs), timeout=30) as r:
        items = json.load(r)
    USER_CATALOGS.mkdir(parents=True, exist_ok=True)
    saved, errors = [], []
    for it in items:
        name = it.get("name", "")
        if it.get("type") != "file" or not name.lower().endswith((".yaml", ".yml", ".json")):
            continue
        url = it.get("download_url")
        if not url:
            continue
        try:
            with urllib.request.urlopen(
                    urllib.request.Request(url, headers={"User-Agent": "s1-soc-investigation"}),
                    timeout=30) as rr:
                content = rr.read().decode()
            dest = USER_CATALOGS / name
            tmp = USER_CATALOGS / (Path(name).stem + ".__tmp__" + Path(name).suffix)
            tmp.write_text(content)
            load_catalog(tmp)  # validate before publishing
            tmp.replace(dest)
            saved.append(name)
        except Exception as e:  # noqa: BLE001
            errors.append({"file": name, "error": str(e)})
    return {"refreshed": len(saved), "files": saved, "errors": errors,
            "repo": f"{CATALOG_REPO}@{CATALOG_REPO_REF}"}


def enrich_users(d: dict) -> dict:
    """Resolve device info per user.

    method="zia" (default) mirrors the Monitored User Enrichment HA flow: it derives
    each user's device from ZIA web logs (event.user -> event.devicehostname) over a
    recent window and picks the most frequent host. This works on any tenant with ZIA.

    method="datatable" reads a config datatable (e.g. monitored_users_enriched) and
    auto-detects the hostname / agent-uuid columns by name.
    """
    emails = [str(e).strip() for e in (d.get("emails") or []) if str(e).strip()]
    if not emails:
        raise ValueError("no users to enrich")
    mock = bool(d.get("mock"))
    method = d.get("method") or "zia"
    config = build_config(mock)
    from s1engine.lrq_client import LRQClient, RequestsTransport
    from s1engine.rate_limiter import TokenBucket
    from s1engine.slicing import iso_z
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz
    transport = None
    if mock:
        from s1engine.testing import FakeTransport
        transport = FakeTransport()
    tp = transport or RequestsTransport(verify_tls=config.verify_tls, pool_maxsize=4)
    client = LRQClient(config.console_url or "https://mock.local", (config.tokens or ["__mock__"])[0],
                       TokenBucket(config.rps, config.burst), tp,
                       poll_interval_s=config.poll_interval_s,
                       query_timeout_s=min(90.0, config.query_timeout_s))
    inlist = ",".join('"' + e.replace('"', '') + '"' for e in emails[:2000])
    now = _dt.now(_tz.utc)

    if method == "zia":
        uf = d.get("userField") or "event.user"
        hf = d.get("hostField") or "event.devicehostname"
        window_days = int(d.get("windowDays", 30))
        pq = (f"serverHost='zia' {hf}=* {uf} in ({inlist})\n"
              f"| group cnt=count() by _user={uf}, _host={hf}\n| sort -cnt\n| limit 5000")
        res = client.run_pq(pq, iso_z(now - _td(days=window_days)), iso_z(now),
                            tenant=config.tenant, account_ids=config.account_ids or None)
        ci = {c: i for i, c in enumerate(res.columns)}
        best = {}
        for r in res.values:
            def g(c):
                return r[ci[c]] if c in ci and ci[c] < len(r) else None
            u, h, c = g("_user"), g("_host"), g("cnt")
            if not u or not h:
                continue
            try:
                cval = float(c)
            except (TypeError, ValueError):
                cval = 1.0
            if u not in best or cval > best[u][1]:
                best[str(u)] = (h, cval)
        enriched = {u: {"hostname": h} for u, (h, _) in best.items()}
        return {"method": "zia", "source": "ZIA event.devicehostname", "matched": len(enriched),
                "requested": len(emails), "enriched": enriched,
                "columns": res.columns, "rows": res.values[:500]}

    # method == "datatable"
    dt = d.get("datatable") or "monitored_users_enriched"
    email_col = d.get("emailCol") or "email"
    pq = f"| dataset 'config://datatables/{dt}'\n| filter {email_col} in ({inlist})\n| limit 5000"
    res = client.run_pq(pq, iso_z(now - _td(days=1)), iso_z(now),
                        tenant=config.tenant, account_ids=config.account_ids or None)
    cols = res.columns
    ci = {c: i for i, c in enumerate(cols)}

    def pick(pats):
        for c in cols:
            if any(pat in c.lower() for pat in pats):
                return c
        return None
    host_c = pick(["devicehostname", "endpoint.name", "hostname", "host", "device", "computer"])
    agent_c = pick(["agent.uuid", "agentuuid", "agent_uuid", "uuid"])
    ecol = email_col if email_col in ci else pick(["email", "user", "principal", "upn"])
    enriched = {}
    for r in res.values:
        def g(c):
            return r[ci[c]] if c and c in ci and ci[c] < len(r) else None
        em = g(ecol)
        if not em:
            continue
        v = {}
        if host_c and g(host_c):
            v["hostname"] = g(host_c)
        if agent_c and g(agent_c):
            v["agent_uuid"] = g(agent_c)
        enriched[str(em)] = v
    return {"method": "datatable", "datatable": dt, "columns": cols, "rows": res.values[:500],
            "host_column": host_c, "agent_column": agent_c, "email_column": ecol,
            "enriched": enriched, "matched": len(enriched), "requested": len(emails)}


def preview_plan(d: dict) -> dict:
    """Estimate the job count for a run without executing it."""
    catalog = load_catalog(d.get("catalog"))
    qids = d.get("queryIds")
    if isinstance(qids, list) and qids:
        keep = set(qids)
        catalog.queries = [q for q in catalog.queries if q.id in keep]
    from s1engine.slicing import slices_for_lookback, day_slices
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz
    sd, ed = d.get("startDate"), d.get("endDate")
    slice_days = int(d.get("sliceDays", 1) or 1)
    if sd and ed:
        s = _dt.fromisoformat(sd).replace(tzinfo=_tz.utc)
        e = _dt.fromisoformat(ed).replace(tzinfo=_tz.utc) + _td(days=1)
        slices = day_slices(s, e, slice_days=slice_days)
    else:
        slices = slices_for_lookback(int(d.get("lookback", 90) or 90), slice_days=slice_days)
    provided = {"entity"} | {k for k, v in (d.get("vars") or {}).items() if str(v).strip()}
    runnable, skipped = 0, []
    for q in catalog.enabled_queries():
        missing = [v for v in q.required_vars() if v not in provided]
        if missing:
            skipped.append({"query": q.id, "missing": missing})
        else:
            runnable += 1
    return {"queries_total": len(catalog.enabled_queries()), "queries_runnable": runnable,
            "queries_skipped": len(skipped), "skipped": skipped[:50],
            "slices": len(slices), "jobs": runnable * len(slices)}


def test_connection(d: dict) -> dict:
    """Confirm the token authenticates by launching a trivial probe query."""
    import time as _t
    from s1engine.lrq_client import LRQClient, RequestsTransport, QuerySyntaxError
    from s1engine.rate_limiter import TokenBucket
    from s1engine.slicing import iso_z
    from datetime import datetime as _dt, timedelta as _td, timezone as _tz
    mock = bool(d.get("mock"))
    config = build_config(mock)
    transport = None
    if mock:
        from s1engine.testing import FakeTransport
        transport = FakeTransport()
    tp = transport or RequestsTransport(verify_tls=config.verify_tls, pool_maxsize=2)
    client = LRQClient(config.console_url or "https://mock.local", (config.tokens or ["__mock__"])[0],
                       TokenBucket(config.rps, config.burst), tp, poll_interval_s=config.poll_interval_s,
                       query_timeout_s=20)
    now = _dt.now(_tz.utc)
    t0 = _t.monotonic()
    try:
        qid, tag = client.launch("dataSource.name=* | limit 1", iso_z(now - _td(hours=1)), iso_z(now),
                                 tenant=config.tenant, account_ids=config.account_ids or None)
        client.cancel(qid, tag)
        return {"ok": True, "elapsed_s": round(_t.monotonic() - t0, 2), "console": config.console_url}
    except QuerySyntaxError:
        return {"ok": True, "note": "authenticated (probe query rejected, auth OK)", "console": config.console_url}
    except Exception as e:  # noqa: BLE001
        return {"ok": False, "error": str(e)[:200], "console": config.console_url}


def list_history(limit: int = 50) -> list:
    """Scan the output folder for past runs (survives restarts)."""
    runs = []
    if OUTPUT_BASE.is_dir():
        for meta in OUTPUT_BASE.glob("*/*/run_meta.json"):
            try:
                m = json.loads(meta.read_text())
            except Exception:
                continue
            rd = meta.parent
            rid = m.get("run_id") or rd.name
            status = "unknown"
            live = _RUNS.get(rid)
            if live:
                status = live["status"]
            elif (rd / "run_status.json").is_file():
                try:
                    status = json.loads((rd / "run_status.json").read_text()).get("status", "unknown")
                except Exception:
                    pass
            runs.append({"run_id": rid, "case": m.get("case"), "entity": m.get("entity"),
                         "catalog": m.get("catalog_name") or m.get("catalog"), "status": status,
                         "started_at": m.get("started_at"), "run_dir": str(rd)})
    runs.sort(key=lambda r: r.get("started_at") or "", reverse=True)
    return runs[:limit]


def resume_run(d: dict) -> dict:
    """Re-run an existing run id from its stored metadata (retries pending/failed slices)."""
    rid = d.get("runId")
    rd = find_run_dir(rid) if rid else None
    if not rd or not (rd / "run_meta.json").is_file():
        raise ValueError("run metadata not found; cannot resume")
    m = json.loads((rd / "run_meta.json").read_text())
    sd = {"case": m["case"], "entity": m["entity"], "catalog": m["catalog"], "runId": rid,
          "lookback": m.get("lookback"), "sliceDays": m.get("sliceDays"),
          "startDate": m.get("startDate"), "endDate": m.get("endDate"),
          "vars": m.get("vars") or {}, "queryIds": m.get("queryIds"),
          "outputDir": m.get("outputDir") or "", "mock": bool(d.get("mock"))}
    return start_run(sd)


def read_result(run_dir: Path, query_id: str) -> dict:
    p = run_dir / "results" / (_safe(query_id) + ".json")
    if not p.is_file():
        return {"error": "no result for query", "columns": [], "values": []}
    data = json.loads(p.read_text())
    return {"query_id": data.get("query_id"), "title": data.get("title"), "pq": data.get("pq"),
            "columns": data.get("columns", []), "values": (data.get("values") or [])[:500],
            "total_rows": len(data.get("values") or []), "warnings": data.get("warnings", [])}


def save_catalog(d: dict) -> dict:
    filename = _safe(d.get("filename") or "").strip()
    content = d.get("content") or ""
    if not filename:
        raise ValueError("filename is required")
    if not (filename.endswith(".yaml") or filename.endswith(".yml") or filename.endswith(".json")):
        filename += ".yaml"
    USER_CATALOGS.mkdir(parents=True, exist_ok=True)
    dest = USER_CATALOGS / filename
    # Keep the real extension on the temp file so load_catalog picks YAML vs JSON.
    tmp = dest.with_name(dest.stem + ".__tmp__" + dest.suffix)
    tmp.write_text(content)
    try:
        cat = load_catalog(tmp)   # validate by parsing
    except Exception as e:
        tmp.unlink(missing_ok=True)
        raise ValueError(f"catalog did not validate: {e}")
    tmp.replace(dest)
    return {"path": str(dest), "name": cat.name, "file": filename,
            "queries": len(cat.enabled_queries())}


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
                                    "output_base": str(OUTPUT_BASE), "exposed": EXPOSED,
                                    "version": os.environ.get("S1IE_VERSION") or ENGINE_VERSION,
                                    "catalog_repo": f"{CATALOG_REPO}@{CATALOG_REPO_REF}",
                                    "datatables": DATATABLES})
        if p == "/api/runs":
            with _RUNS_LOCK:
                runs = [{"run_id": r["run_id"], "case": r["case"], "entity": r["entity"],
                         "status": r["status"], "started_at": r.get("started_at")}
                        for r in _RUNS.values()]
            return self._send(200, {"runs": runs})
        if p == "/api/runhistory":
            return self._send(200, {"runs": list_history()})
        if p == "/api/result":
            run_dir = find_run_dir(qs.get("runId", [""])[0])
            if not run_dir:
                return self._send(404, {"error": "unknown run"})
            return self._send(200, read_result(run_dir, qs.get("query", [""])[0]))
        if p == "/api/activity":
            rid = qs.get("runId", [""])[0]
            since = int(qs.get("since", ["0"])[0])
            reg = _RUNS.get(rid)
            if reg:
                return self._send(200, {"events": reg["activity"].tail(since),
                                        "last_seq": reg["activity"].last_seq(),
                                        "status": reg["status"]})
            run_dir = find_run_dir(rid)  # disk fallback for reopened/past runs
            if not run_dir:
                return self._send(404, {"error": "unknown run"})
            allev = ActivityLog.read_file(run_dir / "activity.jsonl")
            events = [e for e in allev if e.get("seq", 0) > since]
            status = "complete"
            sp = run_dir / "run_status.json"
            if sp.is_file():
                try:
                    status = json.loads(sp.read_text()).get("status", "complete")
                except Exception:
                    pass
            return self._send(200, {"events": events,
                                    "last_seq": (allev[-1]["seq"] if allev else since),
                                    "status": status})
        if p == "/api/status":
            rid = qs.get("runId", [""])[0]
            reg = _RUNS.get(rid)
            if reg:
                cov = None
                if reg["status"] == "running":
                    try:
                        cov = reg["ledger"].coverage(rid)
                    except Exception:
                        cov = None
                else:
                    cov = reg.get("final_coverage")
                return self._send(200, {"status": reg["status"], "stats": reg.get("stats"),
                                        "cache": reg.get("cache"), "error": reg.get("error"),
                                        "verification": reg.get("verification"), "coverage": cov,
                                        "workbook": reg.get("workbook"), "run_dir": reg["run_dir"],
                                        "started_at": reg.get("started_at")})
            run_dir = find_run_dir(rid)  # disk fallback
            if not run_dir:
                return self._send(404, {"error": "unknown run"})
            ver = None
            if (run_dir / "verification.json").is_file():
                try:
                    ver = json.loads((run_dir / "verification.json").read_text())
                except Exception:
                    pass
            st = {}
            if (run_dir / "run_status.json").is_file():
                try:
                    st = json.loads((run_dir / "run_status.json").read_text())
                except Exception:
                    st = {}
            return self._send(200, {"status": st.get("status", "unknown"), "stats": st.get("stats"),
                                    "cache": st.get("cache"), "verification": ver,
                                    "coverage": st.get("coverage"), "workbook": st.get("workbook"),
                                    "run_dir": str(run_dir)})
        if p == "/api/activity_log":
            run_dir = find_run_dir(qs.get("runId", [""])[0])
            if not run_dir or not (run_dir / "activity.jsonl").is_file():
                return self._send(404, {"error": "no activity log for run"})
            data = (run_dir / "activity.jsonl").read_bytes()
            return self._send(200, data, "application/x-ndjson",
                              {"Content-Disposition": f'attachment; filename="{run_dir.name}_activity.jsonl"'})
        if p == "/api/export":
            run_dir = find_run_dir(qs.get("runId", [""])[0])
            if not run_dir:
                return self._send(404, {"error": "unknown run"})
            kind = qs.get("kind", ["results"])[0]
            data, fname = zip_run(run_dir, kind=kind if kind in ("logs", "results", "all") else "results")
            return self._send(200, data, "application/zip",
                              {"Content-Disposition": f'attachment; filename="{fname}"'})
        if p == "/api/catalog":
            path = Path(qs.get("path", [""])[0])
            if not _within(path, _catalog_roots()) or not path.is_file():
                return self._send(404, {"error": "catalog not found or not allowed"})
            try:
                cat = load_catalog(path)
                queries = [{"id": q.id, "title": q.title} for q in cat.queries]
                name = cat.name
            except Exception as e:
                queries, name = [], f"(parse error: {e})"
            return self._send(200, {"path": str(path), "file": path.name, "name": name,
                                    "content": path.read_text(), "queries": queries,
                                    "editable": _within(path, [USER_CATALOGS])})
        if p == "/api/catalog_export":
            path = Path(qs.get("path", [""])[0])
            if not _within(path, _catalog_roots()) or not path.is_file():
                return self._send(404, {"error": "catalog not found"})
            return self._send(200, path.read_bytes(), "application/x-yaml",
                              {"Content-Disposition": f'attachment; filename="{path.name}"'})
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
                subjects = d.get("subjects")
                if isinstance(subjects, list) and subjects:
                    # Batch mode: one run per subject, merging global vars with per-user vars.
                    batch = []
                    base_vars = d.get("vars") or {}
                    for s in subjects:
                        ent = (s.get("entity") or "").strip()
                        if not ent:
                            continue
                        sd = {**d, "entity": ent, "vars": {**base_vars, **(s.get("vars") or {})}}
                        sd.pop("subjects", None)
                        batch.append({"entity": ent, **start_run(sd)})
                    return self._send(200, {"batch": batch, "count": len(batch)})
                return self._send(200, start_run(d))
            if p == "/api/enrich":
                return self._send(200, enrich_users(d))
            if p == "/api/cancel":
                reg = _RUNS.get(d.get("runId"))
                if not reg:
                    return self._send(404, {"error": "unknown run"})
                if reg["status"] != "running":
                    return self._send(200, {"status": reg["status"], "note": "run not active"})
                reg["engine"].request_cancel()
                return self._send(200, {"status": "cancelling"})
            if p == "/api/preview":
                return self._send(200, preview_plan(d))
            if p == "/api/test_connection":
                return self._send(200, test_connection(d))
            if p == "/api/resume":
                return self._send(200, resume_run(d))
            if p == "/api/catalog_save":
                return self._send(200, save_catalog(d))
            if p == "/api/refresh_catalogs":
                return self._send(200, refresh_catalogs_from_repo())
            if p == "/api/validate":
                mock = bool(d.get("mock"))
                if d.get("content"):
                    import tempfile
                    suffix = ".json" if d["content"].lstrip().startswith("{") else ".yaml"
                    tf = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
                    tf.write(d["content"]); tf.close()
                    catalog = load_catalog(tf.name)
                    os.unlink(tf.name)
                elif d.get("catalog"):
                    catalog = load_catalog(d["catalog"])
                else:
                    return self._send(400, {"error": "provide catalog path or content"})
                config = build_config(mock, int(d.get("mockTokens", 1)))
                transport = None
                if mock:
                    from s1engine.testing import FakeTransport
                    # In mock mode, treat a query containing BROKEN as a syntax error
                    # so the validator flow is demonstrable without a live tenant.
                    transport = FakeTransport(fail_query_substr={"BROKEN": "syntax"})
                results = validate_catalog(config, catalog, transport=transport,
                                           window_hours=int(d.get("windowHours", 1)))
                ok = all(r["status"] != "invalid" for r in results)
                return self._send(200, {"ok": ok, "results": results})
            return self._send(404, {"error": "unknown endpoint"})
        except Exception as e:  # noqa: BLE001
            return self._send(400, {"error": str(e)})

    def log_message(self, *a):
        pass


def main() -> int:
    if EXPOSED and not AUTH_TOKEN:
        sys.stderr.write(
            "REFUSING TO START: S1IE_BIND_ALL is set (network exposure) but "
            "S1IE_AUTH_TOKEN is empty.\nSet S1IE_AUTH_TOKEN=<strong-secret> and open the "
            "UI at ?token=<secret>, or unset S1IE_BIND_ALL and publish to the host loopback "
            "only (docker run -p 127.0.0.1:8901:8801 ...).\n")
        return 2
    OUTPUT_BASE.mkdir(parents=True, exist_ok=True)
    USER_CATALOGS.mkdir(parents=True, exist_ok=True)
    st = creds_status()
    print(f"s1-soc-investigation  ->  http://localhost:{PORT}")
    print(f"console               ->  {st['console_url'] or '(not set; use the Connect panel)'}")
    print(f"tokens                ->  {st['num_tokens']} configured")
    print(f"output base           ->  {OUTPUT_BASE}")
    if AUTH_TOKEN:
        print("auth                  ->  token required (?token= or X-Auth-Token)")
    if EXPOSED:
        print(f"exposure              ->  bound to {HOST} (network-reachable); token enforced")
    elif HOST not in ("127.0.0.1", "localhost", "::1"):
        print(f"WARNING               ->  bound to {HOST} without S1IE_BIND_ALL; publish to 127.0.0.1 only.")
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
