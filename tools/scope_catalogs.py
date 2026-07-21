#!/usr/bin/env python3
"""
Classify every catalog query with a `scope` and, for subject-scoped queries that
have no subject filter yet, inject the correct per-source subject filter so they
run scoped to the investigation subject instead of tenant-wide.

Scopes (see catalog guide):
  subject     - must filter to the investigated person/endpoint
  pivot       - scoped by a discovered value (domain/file/app/session/login key)
  environment - intentionally tenant-wide (Top/Unique/totals/rankings/inventory)
  coverage    - tenant-wide source/schema presence checks

Rules
-----
1. A query that already references a subject variable  -> subject (no rewrite).
2. A query that references only a pivot variable        -> pivot.
3. Otherwise (no subject/pivot var, i.e. tenant-wide today):
     - coverage  if it is a source/schema presence panel;
     - environment if it is an aggregate / ranking / inventory panel
       (conservative: only clearly fleet-wide shapes);
     - subject otherwise -> inject a per-source subject filter.

Single-source subject panels are rewritten by inserting `| filter (<expr>)` right
after the source anchor. Multi-source `| union (...)` panels are marked subject
but NOT auto-rewritten (the gate skips them safely until hand-scoped); they are
listed so a human can finish them.

Usage:  python tools/scope_catalogs.py --dry-run [--only dfir_exfil_dlp.yaml ...]
        python tools/scope_catalogs.py --apply   [--only ...]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from s1engine.catalog import load_catalog, SUBJECT_VARS, PIVOT_VARS  # noqa: E402

TEMPLATE_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*(?:\|[^}]*?)?\s*\}\}")

# The subject filter to inject, chosen by which source/schema family a query hits.
# {{entity}} is always set on the run form, so entity-scoped panels always run and
# are always scoped; EDR panels use the endpoint identity vars discovered later.
ENTITY = "{{entity}}"
SUBJ_EDR = ("(agent.uuid == '{{agent_uuid}}' OR endpoint.name contains:anycase('{{hostname}}') "
            "OR src.process.user contains:anycase('{{username}}'))")


def subject_filter_for(pq: str):
    """Return (filter_expr, source_label) for a single-source query, or (None, None)
    if the source can't be identified or it is a multi-source union."""
    low = pq.lower()
    if "| union" in low:
        return None, "union"
    # Prompt Security
    if "serverhost" in low and "prompt-security" in low or "log.violations" in low or "log.user" in low:
        return "log.user contains:anycase('%s')" % ENTITY, "prompt-security"
    # Google Workspace
    if "google_workspace" in low or "actor.applicationinfo" in low or "event.doc_title" in low:
        return ("(actor.email contains:anycase('%s') OR event.owner contains:anycase('%s'))"
                % (ENTITY, ENTITY)), "google_workspace"
    # Salesforce realtime (payload), event-monitoring, audit
    if "detail.payload" in low:
        return "detail.payload.Username contains:anycase('%s')" % ENTITY, "salesforce-realtime"
    if "event_type" in low or "number_of_records" in low or "login_key" in low:
        return "(username contains:anycase('%s') OR USER_ID contains:anycase('%s'))" % (ENTITY, ENTITY), "salesforce-event"
    if "createdbyid" in low or "responsiblenamespaceprefix" in low:
        return "username contains:anycase('%s')" % ENTITY, "salesforce-audit"
    # OpLockdown software inventory (owner is the person)
    if "oplockdown" in low or re.search(r"\bowner\b", low) and "app_name" in low:
        return "owner contains:anycase('%s')" % ENTITY, "oplockdown"
    # ZIA / Zscaler web proxy
    if "event.user" in low or "event.outbytes" in low or "zentotalbytestxclient" in low or "serverhost='{{src_zia" in low or "serverhost='zia'" in low:
        return ("(event.user contains:anycase('%s') OR event.deviceowner contains:anycase('%s'))"
                % (ENTITY, ENTITY)), "zia"
    # SentinelOne EDR (process/file/dns/ip telemetry)
    if ("event.type" in low or "event.category" in low or "src.process" in low
            or "tgt.file" in low or "endpointdevicecontrol" in low or "indicator.name" in low):
        return SUBJ_EDR, "edr"
    return None, "unknown"


AGG_TITLE = re.compile(
    r"\b(top|unique|by source type|allowed vs blocked|installed|inventory|categories|"
    r"block candidates|users with|users requiring|recently observed|candidate list|"
    r"total|over time)\b", re.I)


def is_coverage(q) -> bool:
    t = (q.title + " " + q.notes).lower()
    b = q.pq.lower()
    return ("coverage" in t or "array_agg_distinct( datasource.name" in b.replace(" ", " ")
            or "array_agg_distinct(datasource.name" in b or "by source=serverhost" in b.replace(" ", ""))


def is_environment(q) -> bool:
    """Conservative: only clearly fleet-wide aggregate/ranking/inventory shapes."""
    if AGG_TITLE.search(q.title or ""):
        return True
    b = q.pq.lower()
    # pure count()/estimate_distinct summary with no per-identity group-by
    if re.search(r"\|\s*group\s+[^|]*count\(\)\s*$", b) and " by " not in b.split("group", 1)[-1]:
        return True
    if "estimate_distinct(event.user)" in b and " by " not in b.split("group", 1)[-1]:
        return True
    return False


def classify(q):
    used = {n for n in TEMPLATE_RE.findall(q.pq)}
    if used & set(SUBJECT_VARS):
        return "subject", False   # already scoped
    if used & set(PIVOT_VARS):
        return "pivot", False
    if is_coverage(q):
        return "coverage", False
    if is_environment(q):
        return "environment", False
    return "subject", True        # tenant-wide detail panel -> needs a subject filter


def _first_stage_pipe(s: str) -> int:
    """Index of the first '|' that is a pipeline-stage separator, i.e. NOT the one
    inside a {{var|default}} template. Returns -1 if there is no stage pipe."""
    depth = 0
    i = 0
    while i < len(s):
        two = s[i:i + 2]
        if two == "{{":
            depth += 1; i += 2; continue
        if two == "}}":
            depth = max(0, depth - 1); i += 2; continue
        if s[i] == "|" and depth == 0:
            return i
        i += 1
    return -1


def inject(pq: str, expr: str) -> str:
    s = pq.strip()
    idx = _first_stage_pipe(s)
    if idx == -1:                          # single-stage query, no pipe yet
        return f"{s} | filter ({expr})"
    head, tail = s[:idx], s[idx:]          # tail starts with '|'
    if head.strip():                       # initial predicate present
        return f"{head.rstrip()} | filter ({expr}) {tail}"
    return f"| filter ({expr}) {tail}"     # leading-pipe (EDR) query


class _Q:
    """Minimal shim so classify()/subject_filter_for() work on a raw YAML dict."""
    def __init__(self, d):
        self.id = d.get("id", "")
        self.title = d.get("title", "")
        self.pq = d.get("pq", "")
        self.notes = d.get("notes", "")


def process_file(cf: Path, apply: bool):
    import yaml
    data = yaml.safe_load(cf.read_text())
    counts = {"subject": 0, "pivot": 0, "environment": 0, "coverage": 0}
    rewrites, unions = [], []
    for qd in data.get("queries", []):
        q = _Q(qd)
        scope, needs = classify(q)
        counts[scope] += 1
        if needs:
            expr, src = subject_filter_for(q.pq)
            if expr is None:
                unions.append((q.id, src))       # multi-source union: gate, don't rewrite
            else:
                rewrites.append((q.id, src))
                if apply:
                    qd["pq"] = inject(q.pq, expr)
        if apply:
            qd["scope"] = scope
    if apply:
        # Re-dump. Catalogs are machine-generated (no meaningful comments); keep key
        # order and avoid line-wrapping the long pq bodies.
        cf.write_text(yaml.safe_dump(data, sort_keys=False, default_flow_style=False,
                                     width=100000, allow_unicode=True))
    return counts, rewrites, unions


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--only", nargs="*")
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()
    cats = sorted((ROOT / "catalogs").glob("dfir_*.yaml"))
    if a.only:
        cats = [c for c in cats if c.name in set(a.only)]
    print(f"{'catalog':32} subj piv env cov  | rewrite union-todo")
    tot_rw = tot_un = 0
    for cf in cats:
        if "insider_threat_full" in cf.name:
            continue
        c, rw, un = process_file(cf, a.apply)
        tot_rw += len(rw); tot_un += len(un)
        print(f"{cf.name:32} {c['subject']:4} {c['pivot']:3} {c['environment']:3} {c['coverage']:3}  | {len(rw):7} {len(un)}")
        if a.verbose and un:
            print("     union-todo:", ", ".join(i for i, _ in un))
    print(f"\n{'APPLIED' if a.apply else 'DRY-RUN'}: {tot_rw} queries rewritten, "
          f"{tot_un} union queries left for manual scoping (gated meanwhile).")


if __name__ == "__main__":
    main()
