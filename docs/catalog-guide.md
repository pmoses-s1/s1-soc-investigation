# Catalog guide

The bundled `catalogs/` are a DFIR / insider-threat query library for the SentinelOne
Singularity Data Lake, organized by investigation domain so you can run one phase at a
time or the whole sweep. Every query is written in the engine's template form
(`{{entity}}` plus the variables in the [Variables popup](user-guide.md#4-set-investigation-variables))
and is validated by the [test harness](#validating-the-catalogs) before shipping.

Sources: a real DFIR investigation workbook plus the SOC Investigation Library v2
(coverage, identity, endpoint, collaboration, web/DLP, SaaS, GenAI, and cross-source
pivots). On import, queries were normalized for SDL (`== null` -> `!field`,
`!= null` -> `field = *`, placeholders -> `{{var}}`, `serverHost` -> overridable
`{{src_*|default}}`), de-duplicated by body, and linted; nothing invalid ships.

## Domain catalogs

Pick the catalog for the phase you are working, or the master for everything the
variables allow. Query counts below are as of v0.4.1; the catalog dropdown in the UI shows the live count.

| Catalog | Queries | Focus | What it covers |
|---|---:|---|---|
| `dfir_coverage_identity` | 291 | Coverage & identity | Which sources hold data for the subject; first/last seen, countries, IPs; identity baselining. Run this first to see what telemetry exists before concluding absence. |
| `dfir_identity_access` | 32 | Identity & access | Okta, Azure/Entra, JumpCloud, 1Password, secrets. Logins, MFA, lifecycle, privilege changes, impossible travel. |
| `dfir_endpoint` | 22 | Endpoint / EDR | SentinelOne EDR plus software inventory (oplockdown): USB writes, archive/exfil tooling, large-file staging, logins, print/screenshot artifacts, installed software. |
| `dfir_collab_storage` | 78 | Collaboration & storage | Google Workspace, Slack, OneDrive/Box: file downloads, sharing, deletions, channel joins, mass access. |
| `dfir_web_network` | 52 | Web & network | Zscaler ZIA web proxy, DNS: destinations, uploads, blocked/allowed categories, DLP-relevant web activity. |
| `dfir_saas_apps` | 37 | SaaS & apps | Salesforce (realtime/event/audit), GitHub, Snyk, Navan travel, misc SaaS: logins, report/SOQL volume, config changes, session pivots. |
| `dfir_ai_prompt` | 65 | AI & Prompt Security | GenAI / Prompt Security (prompt-security): data-laundering and policy violations, secrets/sensitive content sent to AI tools, shadow-AI usage. |
| `dfir_exfil_dlp` | 48 | Exfil & DLP | Cross-source exfiltration and data-loss signals (endpoint + web + SaaS staging and transfer). |
| `dfir_cloud` | 3 | Cloud | Cloud control-plane activity (e.g. AWS). |
| `dfir_correlation` | 15 | Cross-source correlation | Quick pivots and multi-source stitching (session keys, login keys, IOC sweeps). |
| `dfir_insider_threat_full` | 640 | Master (full sweep) | Every domain query in one catalog, de-duplicated, for a one-click full investigation. |
| `insider_threat` | 6 | Minimal example | A tiny sample for demos and smoke tests. |

Domain catalogs total 643 queries; the master `dfir_insider_threat_full` is the de-duplicated union.

## How to run a case logically

1. **Coverage first.** Run `dfir_coverage_identity` to confirm which sources have data
   for the subject and to baseline identity. Empty sources are a finding too.
2. **Identity phase.** Run `dfir_identity_access` to establish logins, MFA, geography,
   and privilege changes. Fill in the `hostname` / `agent_uuid` you discover.
3. **Endpoint and web.** With the host/agent set, run `dfir_endpoint` and
   `dfir_web_network` for on-device staging and web/DLP activity.
4. **Collaboration, SaaS, AI.** Run `dfir_collab_storage`, `dfir_saas_apps`, and
   `dfir_ai_prompt` for cloud-app data movement and GenAI exposure.
5. **Correlate.** Use `dfir_correlation` to stitch sessions and pivot IOCs across
   sources, or run `dfir_insider_threat_full` to sweep everything at once.

A query whose required subject variables are unset is **skipped, not failed**, so you
can run the coverage/identity phases first and re-run later phases once you have filled
in the host, agent, IP, or app you discovered.

## Variables and data-source overrides

Queries reference subject variables (`{{entity}}`, `{{hostname}}`, `{{agent_uuid}}`,
`{{ip}}`, `{{username}}`, `{{sf_user_id}}`, `{{session}}`, `{{app_name}}`, `{{domain}}`,
`{{login_key}}`, `{{file_or_title}}`), optional config datatables (`dt_*`), and
data-source names (`src_*`). Source names carry a default (e.g. `{{src_zia|zia}}`), so
queries run out of the box; override one in **Variables** only if your tenant ingests
that source under a different `serverHost`. See the
[user guide](user-guide.md#4-set-investigation-variables).

## Validating the catalogs

The repo ships a query test harness. Lint every catalog offline (no tenant), or
validate against SDL with dummy variables:

```bash
# static lint only (catches == null, obj['key'], | head, sort desc, placeholders)
python -m s1engine.cli validate --lint-only --dir catalogs

# lint + launch each query over a short window with dummy vars (needs credentials)
python -m s1engine.cli validate --dir catalogs

# offline against the fake backend
python -m s1engine.cli validate --dir catalogs --mock
```

The linter's rules are all verified against a live tenant: `field == null` (HTTP 500),
`obj['key']` / `obj."key"` sub-indexing (HTTP 400), `| head` (HTTP 400), and
`sort field desc|asc` (HTTP 400) are rejected; while `field != null`, `field = *`,
top-level `"quoted fields"`, bare case-sensitive `contains 'x'`, and `nolimit` are
valid and are not flagged. `pytest tests/test_catalog_lint.py` fails the build if any
bundled catalog regresses.
