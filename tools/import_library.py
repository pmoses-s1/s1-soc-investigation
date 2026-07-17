#!/usr/bin/env python3
"""
Merge NEW queries from the SOC Investigation Library v2 into the existing dfir_*
catalogs, matched by normalized query body so nothing is duplicated.

    import_library.py <library.yaml> <index.csv> <catalogs_dir> <out_dir>

For each v2 query it: normalizes for SDL (`== null` -> `!field`, `!= null` -> `= *`,
converts <X>/%X% placeholders to {{var}}, parameterizes serverHost to
{{src_*|default}}, bare `contains` -> `contains:anycase`), skips any query that still
fails the static linter (reported), drops queries whose body already exists in a
dfir_ catalog (dedupe) or repeats within v2, then appends the remainder to the
phase-appropriate dfir_ domain catalog and the master. Only changed files are
written to <out_dir> for review/copy.
"""
import csv
import re
import sys
from pathlib import Path

import yaml

LIB, IDX, CATDIR, OUTDIR = (Path(sys.argv[1]), Path(sys.argv[2]),
                            Path(sys.argv[3]), Path(sys.argv[4]))
MASTER = "dfir_insider_threat_full"

# v2 phase -> dfir domain catalog. Large/distinct phases get their own new category.
PHASE_DOMAIN = {
    "000_coverage_identity": "dfir_coverage_identity",   # new category (large: ~300)
    "050_okta": "dfir_identity_access",
    "020_endpoint": "dfir_endpoint",
    "140_software_oplockdown": "dfir_endpoint",
    "030_google_workspace": "dfir_collab_storage",
    "040_slack": "dfir_collab_storage",
    "060_salesforce": "dfir_saas_apps",
    "120_ai_prompt_security": "dfir_ai_prompt",          # new category (distinct: GenAI)
    "100_zia_dlp": "dfir_web_network",
    "900_quick_pivots": "dfir_correlation",
}
# Categories to create if they do not exist yet (name shown in the UI dropdown).
NEW_DOMAINS = {
    "dfir_coverage_identity": "DFIR: Coverage & identity (library)",
    "dfir_ai_prompt": "DFIR: AI & Prompt Security",
}

PLACE = [("%EMAIL%", "{{entity}}"), ("%USERNAME%", "{{username}}"), ("%AGENTUUID%", "{{agent_uuid}}"),
         ("%HOSTNAME%", "{{hostname}}"), ("%IP%", "{{ip}}"), ("%SF_USER_ID%", "{{sf_user_id}}"),
         ("%SESSION%", "{{session}}"), ("%SESSION_KEY%", "{{session}}"), ("%LOGIN_KEY%", "{{login_key}}"),
         ("%DOMAIN%", "{{domain}}"), ("%APP_NAME%", "{{app_name}}"), ("%FILE_OR_TITLE%", "{{file_or_title}}"),
         ("%USER%", "{{username}}"), ("%HOST%", "{{hostname}}"),
         ("<IP>", "{{ip}}"), ("<SESSION>", "{{session}}"), ("<SESSION_KEY>", "{{session}}"),
         ("<HOST>", "{{hostname}}"), ("<HOSTNAME>", "{{hostname}}"), ("<USER>", "{{username}}"),
         ("<USERNAME>", "{{username}}"), ("<AGENTUUID>", "{{agent_uuid}}"), ("<EMAIL>", "{{entity}}"),
         ("<LOGIN_KEY>", "{{login_key}}"), ("<DOMAIN>", "{{domain}}"), ("<APP_NAME>", "{{app_name}}"),
         ("<FILE_OR_TITLE>", "{{file_or_title}}"), ("<SF_USER_ID>", "{{sf_user_id}}")]


def slug(t):
    return re.sub(r"[^a-z0-9]+", "_", t.lower()).strip("_")


def convph(s):
    for a, b in PLACE:
        s = s.replace(a, b)
    s = re.sub(r"%([A-Za-z][A-Za-z0-9_]*)%", lambda m: "{{" + slug(m.group(1)) + "}}", s)
    s = re.sub(r"<([A-Za-z][A-Za-z0-9_]*)>", lambda m: "{{" + slug(m.group(1)) + "}}", s)
    return s


def paramsh(s):
    def r(m):
        q, v = m.group(1), m.group(2)
        return m.group(0) if not v.strip() else f"serverHost={q}{{{{src_{slug(v)}|{v}}}}}{q}"
    return re.sub(r"serverHost\s*=\s*(['\"])(.*?)\1", r, s)


def drop_bracket_index(pq):
    """Fix the unsupported `let X=string(obj['key'])` sub-indexing pattern (HTTP 400)
    by removing that pipe-stage and any references to X in the filter/columns. Works on
    both multi-line and single-line queries (matches the `| let ... [ 'key' ] ...` stage
    directly rather than splitting on newlines)."""
    if not re.search(r"[A-Za-z0-9_.]+\[\s*('[^']*'|\"[^\"]*\")\s*\]", pq):
        return pq
    bad = []

    def repl(m):
        bad.append(m.group(1))
        return ""
    # Remove a `| let VAR = ... ['key'] ...` stage up to (but not including) the next pipe.
    s = re.sub(r"\|\s*let\s+(\w+)\s*=[^|]*\[\s*(?:'[^']*'|\"[^\"]*\")\s*\][^|]*", repl, pq)
    for v in map(re.escape, bad):
        s = re.sub(r"\s*OR\s*\(\s*!isempty\(%s\)\s*&&\s*%s\s*!=\s*'\[\]'\s*\)" % (v, v), "", s)
        s = re.sub(r"\(\s*!isempty\(%s\)\s*&&\s*%s\s*!=\s*'\[\]'\s*\)\s*OR\s*" % (v, v), "", s)
        s = re.sub(r",\s*%s\b" % v, "", s)
        s = re.sub(r"\b%s\s*,\s*" % v, "", s)
    return s


def normalize(pq):
    # Only transformations verified against the live tenant:
    #   == null -> !field (== null is HTTP 500);  != null -> field = * (canonical existence)
    #   <X>/%X% placeholders -> {{var}};  serverHost -> {{src_*|default}};  drop obj['key'].
    # Bare `contains` and `nolimit` are VALID and are left unchanged.
    s = pq
    s = re.sub(r"([\w.]+)\s*==\s*null\b", r"!\1", s)
    s = re.sub(r"([\w.]+)\s*!=\s*null\b", r"\1 = *", s)
    s = convph(s)
    s = paramsh(s)
    s = drop_bracket_index(s)
    s = re.sub(r"\n\s*\n", "\n", s).strip()   # tidy blank lines left by dropped stages
    return s


BAD = [re.compile(p) for p in [
    r"==\s*null\b", r"[A-Za-z0-9_.]+\[\s*('[^']*'|\"[^\"]*\")\s*\]",
    r"[A-Za-z0-9_]+\.\"[^\"]*\"", r"<[A-Za-z][A-Za-z0-9_]*>|%[A-Za-z][A-Za-z0-9_]*%",
    r"\|\s*head\b", r"\bsort\b[^|\n]*\b(?:desc|asc)\b"]]


def lint(s):
    return [b.pattern for b in BAD if b.search(s)]


def canon(pq):
    return re.sub(r"\s+", " ", pq or "").strip()


class LS(str):
    pass


yaml.add_representer(LS, lambda d, x: d.represent_scalar("tag:yaml.org,2002:str", x, style="|"))

# Load existing dfir_ catalogs (domain files + master).
domain = {}          # name -> data dict
existing_canon = set()
existing_ids = set()
for p in sorted(CATDIR.glob("dfir_*.yaml")):
    data = yaml.safe_load(p.read_text())
    domain[p.stem] = data
    for q in data.get("queries", []):
        existing_ids.add(q.get("id"))
        existing_canon.add(canon(q.get("pq")))
# Create any new categories that do not exist yet.
for name, disp in NEW_DOMAINS.items():
    domain.setdefault(name, {"name": disp, "queries": []})

# v2 id -> phase.
phase = {}
with open(IDX) as f:
    for r in csv.DictReader(f):
        phase[r["id"]] = r["phase"]

lib = yaml.safe_load(LIB.read_text())
added, skipped_lint = {}, []
dup_existing = dup_v2 = 0
new_canon = set()
for q in lib.get("queries", []):
    qid = q.get("id")
    npq = normalize(q.get("pq") or "")
    if not npq.strip():
        skipped_lint.append((qid, ["empty pq after normalization"]))
        continue
    issues = lint(npq)
    if issues:
        skipped_lint.append((qid, issues))
        continue
    c = canon(npq)
    if c in existing_canon:
        dup_existing += 1
        continue
    if c in new_canon:
        dup_v2 += 1
        continue
    dom = PHASE_DOMAIN.get(phase.get(qid), "dfir_correlation")
    if dom not in domain:
        dom = "dfir_correlation"
    nid = qid
    i = 2
    while nid in existing_ids:
        nid = f"{qid}-{i}"
        i += 1
    existing_ids.add(nid)
    new_canon.add(c)
    nq = {"id": nid, "title": q.get("title", nid)}
    if q.get("notes"):
        nq["notes"] = q["notes"]
    nq["pq"] = LS(npq) if "\n" in npq else npq
    if q.get("merge"):
        nq["merge"] = q["merge"]
    domain[dom].setdefault("queries", []).append(nq)
    domain[MASTER].setdefault("queries", []).append(dict(nq))
    added[dom] = added.get(dom, 0) + 1

OUTDIR.mkdir(parents=True, exist_ok=True)
changed = set(added) | {MASTER}
for name in changed:
    data = domain[name]
    for q in data.get("queries", []):
        if isinstance(q.get("pq"), str) and "\n" in q["pq"]:
            q["pq"] = LS(q["pq"])
    (OUTDIR / f"{name}.yaml").write_text(
        yaml.dump(data, sort_keys=False, allow_unicode=True, width=100000))

print("added per domain:", added)
print("total added     :", sum(added.values()))
print("dup vs existing :", dup_existing, " dup within v2:", dup_v2)
print("skipped (lint)  :", len(skipped_lint))
for qid, iss in skipped_lint[:40]:
    print("   skip", qid, iss)
print("files written   :", sorted(changed))
