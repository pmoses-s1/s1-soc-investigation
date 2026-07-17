"""
Static PowerQuery / catalog linter.

Validates catalogs OFFLINE (no tenant) by flagging the syntax pitfalls that make
SDL reject a query at run time, so they are caught before a 90-day investigation:

  - `field == null`            -> SDL returns HTTP 500. Use `!field` for empty/absent.
                                  (`field != null` is valid and is NOT flagged.)
  - `obj['key']` / obj."key"   -> bracket / dot-quote sub-field indexing is rejected
                                  (HTTP 400). A top-level "quoted field" reference is
                                  fine and is not flagged.
  - `<X>` or `%X%`             -> un-converted placeholder; use `{{var}}`.
  - bare `contains 'x'`        -> use `contains:anycase("x")` (bare contains is 400).
  - `| head N`                 -> invalid; use `| limit N`.
  - `sort field desc|asc`      -> invalid; use `sort -field` / `sort field`.

These mirror the PowerQuery rules the engine's error classification enforces live,
so a catalog that lints clean here should not be marked `permanent` mid-run for
these reasons.
"""

from __future__ import annotations

import re
from typing import Dict, List

from .catalog import Catalog

# Each check: (regex, message). Kept deliberately conservative to avoid false
# positives (e.g. `!= null` and top-level "quoted fields" are valid, so excluded).
_CHECKS = [
    (re.compile(r"==\s*null\b"),
     "`== null` is rejected by SDL (HTTP 500); use `!field` for empty/absent"),
    (re.compile(r"[A-Za-z0-9_.]+\[\s*('[^']*'|\"[^\"]*\")\s*\]"),
     "bracket string-indexing obj['key'] is unsupported (HTTP 400)"),
    (re.compile(r"[A-Za-z0-9_]+\.\"[^\"]*\""),
     "dot-quote sub-field obj.\"key\" is unsupported (HTTP 400)"),
    (re.compile(r"<[A-Za-z][A-Za-z0-9_]*>|%[A-Za-z][A-Za-z0-9_]*%"),
     "un-converted placeholder (<X> or %X%); use {{var}}"),
    (re.compile(r"\bcontains\s+['\"]"),
     "bare `contains`; use `contains:anycase(\"...\")`"),
    (re.compile(r"\|\s*head\b"),
     "`| head` is invalid; use `| limit N`"),
    (re.compile(r"\bsort\b[^|\n]*\b(?:desc|asc)\b"),
     "`sort field desc/asc` is invalid; use `sort -field` / `sort field`"),
]


def lint_query(pq: str) -> List[str]:
    """Return a list of lint messages for a single PowerQuery body (may be empty)."""
    return [msg for rx, msg in _CHECKS if rx.search(pq or "")]


def lint_catalog(cat: Catalog) -> Dict[str, List[str]]:
    """Map of query_id -> list of lint issues, for queries that have any."""
    out: Dict[str, List[str]] = {}
    for q in cat.queries:
        issues = lint_query(q.pq)
        if issues:
            out[q.id] = issues
    return out
