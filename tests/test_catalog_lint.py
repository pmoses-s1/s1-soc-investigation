"""Every bundled catalog must lint clean (no SDL-rejecting PowerQuery patterns)."""

from pathlib import Path

from s1engine.catalog import load_catalog
from s1engine.lint import lint_catalog, lint_query


def test_bundled_catalogs_lint_clean():
    root = Path(__file__).resolve().parent.parent / "catalogs"
    problems = {}
    for p in sorted(list(root.glob("*.yaml")) + list(root.glob("*.yml"))):
        issues = lint_catalog(load_catalog(p))
        if issues:
            problems[p.name] = issues
    assert not problems, f"catalog lint issues: {problems}"


def test_linter_flags_known_bad_patterns():
    assert lint_query("x | filter owner == null")          # 500
    assert lint_query("x | let s=a['Sensitive Data']")     # bracket index 400
    assert lint_query("x contains 'foo'")                  # bare contains
    assert lint_query("x | head 5")                        # head
    assert lint_query("x | sort ts desc")                  # sort desc
    assert lint_query("x | filter name contains:anycase('<APP_NAME>')")  # placeholder


def test_linter_allows_valid_patterns():
    # != null and field=* (existence) and top-level quoted fields are all valid.
    assert not lint_query("x | filter ts != null | limit 1")
    assert not lint_query("x | filter serverHost=* | limit 1")
    assert not lint_query('x | filter "Source User" contains:anycase("a") | limit 1')
    assert not lint_query("x | filter name contains:anycase('{{app_name}}') | sort -ts | limit 10")
