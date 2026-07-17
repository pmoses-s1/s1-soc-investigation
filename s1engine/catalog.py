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


@dataclass
class Catalog:
    name: str
    queries: List[Query]

    def enabled_queries(self) -> List[Query]:
        return [q for q in self.queries if q.enabled]

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
        queries.append(Query(
            id=qid,
            title=q.get("title", qid),
            pq=q["pq"],
            enabled=q.get("enabled", True),
            merge=MergeSpec.from_dict(q.get("merge")),
            tenant=q.get("tenant"),
            account_ids=q.get("account_ids"),
            notes=q.get("notes", ""),
        ))
    if not queries:
        raise ValueError(f"Catalog {name} has no queries")
    return Catalog(name=name, queries=queries)
