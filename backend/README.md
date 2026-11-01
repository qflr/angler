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

`ANGLER_DATA_SOURCE` decides where responses come from, and every `/api/*` response echoes it in the
`X-Angler-Data-Source` header so nobody mistakes placeholder data for real data.

| value | meaning |
|---|---|
| `fixture` | Phase 0 default. One static example record per endpoint, copied from the contract. Not traffic. |
| `db` | Phase 3+. Real CVEs from the pipeline and real hits from the honeypot. Empty until something real arrives. |

## Render web service (dashboard API)

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

## Render Workflows notes (confirmed against render.com/docs/workflows, Nov 2026)

- Package `render>=1.0.1`; `from render import TaskContext, Workflows, Retry`; `app = Workflows()`; `@app.task`.
- There is **no `ctx.step()`**. `TaskContext` has one method, `ctx.run(task, *args)`, which runs a subtask on
  its own compute with its own retries. Checkpoints = one subtask per stage, chained from an `async` parent.
- Retries: `@app.task(retry=Retry(max_retries=3, wait_duration_ms=1000, backoff_scaling=1.5))`.
- Entry point calls `app.start()`; deployed as a *Workflow* service with start command `python <entry>.py`.
- **No built-in scheduling.** A Render Cron Job triggers runs through the SDK client
  (`Render().workflows.start_task("<workflow-slug>/<task>", [...])`, needs `RENDER_API_KEY`).
- Local: `render workflows dev -- python <entry>.py` (CLI 2.12+, port 8120), point the SDK at it with `RENDER_TASKS_URL`.
