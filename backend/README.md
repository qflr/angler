# Angler backend

FastAPI service for the dashboard, plus (from Phase 1) the Render Workflows ingestion pipeline.
The API contract lives in [`docs/api-contract.md`](../docs/api-contract.md); the Pydantic models in
`app/schemas.py` mirror it and `tests/test_api.py` fails if they drift from `frontend/src/data/types.ts`.

## Run locally

```bash
cd backend
python -m venv .venv && .venv/Scripts/activate   # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
uvicorn app.main:app --reload                     # http://localhost:8000/docs
pytest -q
```

Point the frontend at it with `VITE_API_URL=http://localhost:8000` in `frontend/.env`.

## Data source

Every `/api/*` response is read from the pipeline database (header `X-Angler-Data-Source: db`).
There are no fixtures: with no honeypot hits yet, `/api/events` and `/api/actors` are empty lists and
`total_hits` is 0. CVE `status` comes from the documented rules in `app/triage.py`; `severity` and
`patch_status` are `"unknown"` when no source has an answer.

## Deploy (Blueprint)

`backend/render.yaml` defines everything: Postgres `angler-db`, web service `angler-api`, workflow
`angler-pipeline`, and cron job `angler-refresh` (every 15 min it runs `trigger.py`, which starts
`angler-pipeline/refresh`). Render Dashboard: New, Blueprint, repo `qflr/angler`, Blueprint Path
`backend/render.yaml`. Render prompts for `RENDER_API_KEY` (cron only) and `FRONTEND_ORIGINS`.

`DATABASE_URL` switches `app/db.py` from SQLite to Postgres; locally it stays SQLite.

## Render web service (dashboard API, manual setup alternative)

| setting | value |
|---|---|
| Root Directory | `backend` |
| Runtime | Python 3 (version pinned by `.python-version`) |
| Build Command | `pip install -r requirements.txt` |
| Start Command | `uvicorn app.main:app --host 0.0.0.0 --port $PORT` |
| Health Check Path | `/healthz` |
| Env | `FRONTEND_ORIGINS=https://<frontend>.onrender.com` (comma-separated). localhost on any port is always allowed. |

## CVE ingestion (Phase 1)

Pulls `CVEProject/cvelistV5` changes from `cves/deltaLog.json` (30 days of repo updates, ~2 MB
gzipped), dedups by CVE ID, tags new vs updated, and upserts into SQLite (`angler.db`, gitignored).

```bash
python -m app.run_local                 # one pull since the stored cursor (first run: last 24h)
python -m app.run_local --every 900     # demo mode, every 15 min
python -m app.run_local --since 2026-11-01T00:00:00.000Z   # replay a window; dedup makes it a no-op
```

Pipeline (`app/pipeline.py`), one Workflows task per checkpoint:
`ingest_cves` → `plan_cve_delta` → `ingest_cve_batch` × N in parallel → `commit_cve_cursor`.
The cursor only moves after every batch is done, failed fetches go to `ingest_pending` and retry
next run, and an older copy of a record never overwrites a newer one.

Test gate result (live data, Nov 1): run 1 stored 845 CVEs (79 new, 766 updated) in 9 s; run 2 found
nothing new; replaying the same 24 h window re-fetched 845 and wrote 0 (all unchanged).

Deploy caveat: Workflows runs each task on its own compute, so a shared SQLite file only works
locally. Deployed runs need Postgres.

## Enrichment (Phase 2)

`python -m app.run_local` now pulls, then enriches (`--enrich-only` skips the pull):

| job | source | writes |
|---|---|---|
| KEV | CISA KEV JSON | `kev`, `kev_date_added`; `kev` change rows dated by CISA's dateAdded; backfills KEV additions from the last 30 days |
| Patch | OSV.dev (CVE record + GHSA aliases), GitHub Advisories API if `GITHUB_TOKEN`, then the CVE record's version ranges | `patch_status` patched/partial/unpatched or NULL if no source knows, `patch_source`, `fixed_versions_json`; `patched` change rows only on an observed transition |
| Severity | NVD 2.0 API, only for CVEs whose record had no CVSS (throttled; `NVD_API_KEY` speeds it up) | `cvss`, `severity`, `severity_source = nvd` |

Test gate (live, Nov 1): CVE-2024-3400, -4577, -23897, CVE-2021-44228 all flagged KEV; 3400 patched
from its record (PAN-OS 10.2.9-h1 / 11.0.4-h1 / 11.1.2-h3), 4577 and 23897 patched via OSV/GHSA;
731/883 tracked CVEs patched, 137 unknown. NVD had no score yet for any of the 28 unscored CVEs.

## Honeypot (Phase 4)

`honeypot/sensor.py` is a low-interaction decoy (stdlib only): it answers like a Windows XAMPP box
(Apache 2.4.58 + PHP 8.2.12, the CVE-2024-4577 target), logs every request, and never executes
anything it receives. Hits ship in batches to `POST /ingest/events` (header `X-Ingest-Key`), spooling
locally if the API is down. The API classifies each hit (`app/classify.py`: targeted = carries a
CVE-2024-4577 probe/exploit, else noise; stage recon/probe/exploit), adds geo/ASN (`app/geoip.py`,
ip-api.com, cached per IP), and hides test traffic (header `X-Angler-Test: 1`, or any non-public source IP).

VM install: copy `honeypot/` to the VM, then `sudo INGEST_KEY=... bash install.sh`. It runs as an
unprivileged systemd service that can bind 80/443 and write only `/var/lib/angler`.
Local test (loopback only): `python honeypot/sensor.py --host 127.0.0.1 --port 8080`.

## Render Workflows notes (confirmed against render.com/docs/workflows, Nov 2026)

- Package `render>=1.0.1`; `from render import TaskContext, Workflows, Retry`; `app = Workflows()`; `@app.task`.
- There is **no `ctx.step()`**. `TaskContext` has one method, `ctx.run(task, *args)`, which runs a subtask on
  its own compute with its own retries. Checkpoints = one subtask per stage, chained from an `async` parent.
- Retries: `@app.task(retry=Retry(max_retries=3, wait_duration_ms=1000, backoff_scaling=1.5))`.
- Entry point calls `app.start()`; deployed as a *Workflow* service with start command `python <entry>.py`.
- **No built-in scheduling.** A Render Cron Job triggers runs through the SDK client
  (`Render().workflows.start_task("<workflow-slug>/<task>", [...])`, needs `RENDER_API_KEY`).
- Local: `render workflows dev -- python <entry>.py` (CLI 2.12+, port 8120), point the SDK at it with `RENDER_TASKS_URL`.
