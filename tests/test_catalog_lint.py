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
    assert lint_query("x | filter owner == null")          # 500 (verified)
    assert lint_query("x | let s=a['Sensitive Data']")     # bracket index 400 (verified)
    assert lint_query("x | head 5")                        # head 400 (verified)
    assert lint_query("x | sort ts desc")                  # sort desc 400 (verified)
    assert lint_query("x | filter name contains:anycase('<APP_NAME>')")  # placeholder


def test_linter_allows_valid_patterns():
    # All verified valid against the live tenant, so must NOT be flagged:
    assert not lint_query("x | filter ts != null | limit 1")               # != null
    assert not lint_query("x | filter serverHost=* | limit 1")             # field=* existence
    assert not lint_query('x | filter "Source User" contains:anycase("a") | limit 1')  # quoted field
    assert not lint_query("x | filter p contains 'exe' | limit 1")          # bare (case-sensitive) contains
    assert not lint_query("x | nolimit")                                    # nolimit is valid
    assert not lint_query("x | filter name contains:anycase('{{app_name}}') | sort -ts | limit 10")
