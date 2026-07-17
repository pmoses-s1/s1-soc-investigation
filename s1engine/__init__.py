"""
s1-investigation-engine
========================

An execution engine for running a standard investigation query catalog across
long (90+ day) lookbacks over the SentinelOne Singularity Data Lake, without
hitting the timeouts, rate limits, and silent query drops that break naive
notebook automation.

Core idea: the unit of work is one query x one time-slice, not one query over
the whole window. Thousands of small, independent, individually retryable and
cacheable jobs replace a handful of giant atomic ones.

Phases implemented here:
  Phase 0 - day-slicing, a durable SQLite job ledger, resume, retry.
  Phase 1 - token-bucket rate governor, worker pool, multi service-user
            round-robin, and AIMD adaptive concurrency.

See README.md for the full roadmap (Phases 2-4: content-addressed cache,
merge-aware workbook export, orchestrator UX).
"""

__version__ = "0.4.0"
