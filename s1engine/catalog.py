"""
Query catalog model.

A catalog is your standard investigation query set: the queries you run on
every forensic / insider-threat case. Each entry carries the PowerQuery body
plus a `merge` strategy that tells the engine how to reassemble the query's
sliced results back into one table (see merge.py).

Query bodies may contain `{{entity}}` (and any extra template vars passed at
runtime), substituted per investigation. Loads from YAML if PyYAML is present,
otherwise JSON.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml  # type: ignore
    _HAVE_YAML = True
except Exception:  # pragma: no cover - optional dep
    _HAVE_YAML = False


# {{name}}  -> required variable (skips the query if unset)
# {{name|default}} -> optional variable; uses `default` when unset, never skips.
#                     Used for data-source names (serverHost) so the catalog runs
#                     out of the box but each source is overridable per tenant.
_TEMPLATE_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_]+)\s*(?:\|([^}]*?))?\s*\}\}")

# ---------------------------------------------------------------- scope model
# Every query is one of four scopes (see the catalog guide). The engine uses this
# to decide whether a query MUST be filtered to the investigation subject before
# it runs, so a single-subject investigation never silently pulls the whole tenant.
#
#   subject     - must filter to the investigated person/endpoint. Hard-skipped
#                 unless at least one of its subject variables is populated.
#   pivot       - scoped by a discovered value (domain, file, app, session,
#                 login key). Hard-skipped unless a referenced pivot var is set.
#   environment - intentionally tenant-wide (Top Users, Unique Users, totals,
#                 rankings). Runs fleet-wide by design; labeled so the analyst
#                 knows the results are not subject-specific.
#   coverage    - tenant-wide source/schema presence checks. Runs fleet-wide.
VALID_SCOPES = ("subject", "pivot", "environment", "coverage")

# Variables that scope a query to the investigated person or endpoint. A query is
# considered "subject-filtered" when it references at least one of these.
SUBJECT_VARS = (
    "entity", "username", "hostname", "agent_uuid", "ip",
    "sf_user_id", "salesforce_user_id", "email", "user_id", "upn",
)
# Variables that scope a query by a discovered pivot value (not the subject
# identity itself). A query referencing one of these is a "pivot" query.
PIVOT_VARS = (
    "domain", "file_or_title", "app_name", "session", "login_key",
)


@dataclass
class MergeSpec:
    """How to combine per-slice results for one query.

    kind:
      "aggregate" - group/count style. Re-aggregate across slices using the
                    column lists below.
      "rows"      - LOG / row-level. Union rows with column alignment.
    """
    kind: str = "rows"
    key_cols: List[str] = field(default_factory=list)
    sum_cols: List[str] = field(default_factory=list)
    min_cols: List[str] = field(default_factory=list)
    max_cols: List[str] = field(default_factory=list)
    distinct_cols: List[str] = field(default_factory=list)  # NOT additive; flagged approximate

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> "MergeSpec":
        if not d:
            return cls(kind="rows")
        return cls(
            kind=d.get("kind", "rows"),
            key_cols=list(d.get("key_cols", [])),
            sum_cols=list(d.get("sum_cols", [])),
            min_cols=list(d.get("min_cols", [])),
            max_cols=list(d.get("max_cols", [])),
            distinct_cols=list(d.get("distinct_cols", [])),
        )


@dataclass
class Query:
    id: str
    title: str
    pq: str
    enabled: bool = True
    merge: MergeSpec = field(default_factory=MergeSpec)
    tenant: Optional[bool] = None
    account_ids: Optional[List[str]] = None
    notes: str = ""
    scope: Optional[str] = None  # subject|pivot|environment|coverage (see VALID_SCOPES)

    def render(self, variables: Dict[str, str]) -> str:
        """Substitute {{var}} / {{var|default}} placeholders.

        A provided, non-empty value wins. Otherwise the inline default is used
        if present. A variable with neither a value nor a default raises (but the
        engine skips such queries before rendering; see required_vars)."""
        def repl(m: "re.Match[str]") -> str:
            name, default = m.group(1), m.group(2)
            if name in variables and str(variables[name]).strip():
                return str(variables[name])
            if default is not None:
                return default
            raise KeyError(
                f"Query '{self.id}' references {{{{{name}}}}} but no value "
                f"was provided. Pass it via --var {name}=... (entity is set "
                f"automatically)."
            )
        return _TEMPLATE_RE.sub(repl, self.pq)

    def required_vars(self) -> List[str]:
        """Variables that gate execution: a name is required only if it appears
        at least once WITHOUT an inline default. Defaulted names never skip."""
        required = set()
        for name, default in _TEMPLATE_RE.findall(self.pq):
            if not default:
                required.add(name)
        return sorted(required)

    def template_vars(self) -> List[tuple]:
        """All (name, default) pairs used by this query; default is '' if none."""
        seen: Dict[str, str] = {}
        for name, default in _TEMPLATE_RE.findall(self.pq):
            # Prefer a non-empty default if any occurrence supplies one.
            if name not in seen or (default and not seen[name]):
                seen[name] = default or ""
        return sorted(seen.items())

    def referenced_var_names(self) -> set:
        """Every {{var}} name used in the body (ignores defaults)."""
        return {name for name, _ in _TEMPLATE_RE.findall(self.pq)}

    def referenced_subject_vars(self) -> List[str]:
        """Subject variables (SUBJECT_VARS) the body filters on, in a stable order."""
        used = self.referenced_var_names()
        return [v for v in SUBJECT_VARS if v in used]

    def referenced_pivot_vars(self) -> List[str]:
        """Pivot variables (PIVOT_VARS) the body filters on, in a stable order."""
        used = self.referenced_var_names()
        return [v for v in PIVOT_VARS if v in used]

    def effective_scope(self) -> str:
        """The declared scope, or one inferred from the body for legacy catalogs.

        Inference (only when `scope` is unset): a body that references a subject
        variable is `subject`; one that references only a pivot variable is
        `pivot`; anything else defaults to `environment` (tenant-wide). Coverage is
        only ever set explicitly, since it is not distinguishable from environment
        by variable usage alone."""
        if self.scope in VALID_SCOPES:
            return self.scope
        if self.referenced_subject_vars():
            return "subject"
        if self.referenced_pivot_vars():
            return "pivot"
        return "environment"

    def scope_gate(self, provided: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Whether this query is allowed to run given the populated variables.

        Returns None if the query may run, or a skip descriptor
        ``{"reason": ..., "scope": ..., "needs": [...]}`` if it must be skipped.

        - subject/pivot: must reference at least one of its scope variables AND
          have at least one of those populated (non-empty). A subject query with
          no subject filter at all is an authoring bug (also caught by the linter)
          and is skipped rather than run tenant-wide.
        - environment/coverage: never gated on the subject."""
        scope = self.effective_scope()
        if scope not in ("subject", "pivot"):
            return None
        refs = (self.referenced_subject_vars() if scope == "subject"
                else self.referenced_pivot_vars())
        if not refs:
            return {"reason": f"{scope}_scope_no_filter", "scope": scope, "needs": []}
        populated = [v for v in refs if str(provided.get(v, "")).strip()]
        if not populated:
            return {"reason": f"no_{scope}_value", "scope": scope, "needs": refs}
        return None


@dataclass
class Catalog:
    name: str
    queries: List[Query]

    def enabled_queries(self) -> List[Query]:
        return [q for q in self.queries if q.enabled]

    def scope_counts(self) -> Dict[str, int]:
        """How many queries fall into each scope (using effective_scope)."""
        out: Dict[str, int] = {s: 0 for s in VALID_SCOPES}
        for q in self.enabled_queries():
            out[q.effective_scope()] = out.get(q.effective_scope(), 0) + 1
        return out

    def required_vars(self) -> List[str]:
        out: set = set()
        for q in self.queries:
            out.update(q.required_vars())
        return sorted(out)

    def template_vars(self) -> Dict[str, str]:
        """Union of every (name -> default) used across the catalog. Default is
        '' for required subject variables, or the inline default for overridable
        ones (e.g. data-source names). A name required anywhere stays required
        (empty default) even if another query defaults it."""
        required = set()
        defaults: Dict[str, str] = {}
        for q in self.enabled_queries():
            for name, default in q.template_vars():
                if default:
                    defaults.setdefault(name, default)
                else:
                    required.add(name)
        out: Dict[str, str] = {}
        for name in set(defaults) | required:
            out[name] = "" if name in required else defaults.get(name, "")
        return dict(sorted(out.items()))


def load_catalog(path: str | Path) -> Catalog:
    p = Path(path)
    text = p.read_text()
    if p.suffix.lower() in (".yaml", ".yml"):
        if not _HAVE_YAML:
            raise RuntimeError(
                "Catalog is YAML but PyYAML is not installed. "
                "pip install pyyaml, or use a .json catalog."
            )
        data = yaml.safe_load(text)
    else:
        data = json.loads(text)

    name = data.get("name") or p.stem
    queries: List[Query] = []
    seen_ids: set = set()
    for i, q in enumerate(data.get("queries", [])):
        qid = q.get("id") or f"q{i+1:03d}"
        if qid in seen_ids:
            raise ValueError(f"Duplicate query id '{qid}' in catalog {name}")
        seen_ids.add(qid)
        if not q.get("pq"):
            raise ValueError(f"Query '{qid}' has no 'pq' body")
        scope = q.get("scope")
        if scope is not None:
            scope = str(scope).strip().lower() or None
            if scope not in VALID_SCOPES:
                raise ValueError(
                    f"Query '{qid}' has invalid scope '{q.get('scope')}'; "
                    f"expected one of {', '.join(VALID_SCOPES)}")
        queries.append(Query(
            id=qid,
            title=q.get("title", qid),
            pq=q["pq"],
            enabled=q.get("enabled", True),
            merge=MergeSpec.from_dict(q.get("merge")),
            tenant=q.get("tenant"),
            account_ids=q.get("account_ids"),
            notes=q.get("notes", ""),
            scope=scope,
        ))
    if not queries:
        raise ValueError(f"Catalog {name} has no queries")
    return Catalog(name=name, queries=queries)
