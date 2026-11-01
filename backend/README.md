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

## Render Workflows notes (confirmed against render.com/docs/workflows, Nov 2026)

- Package `render>=1.0.1`; `from render import TaskContext, Workflows, Retry`; `app = Workflows()`; `@app.task`.
- There is **no `ctx.step()`**. `TaskContext` has one method, `ctx.run(task, *args)`, which runs a subtask on
  its own compute with its own retries. Checkpoints = one subtask per stage, chained from an `async` parent.
- Retries: `@app.task(retry=Retry(max_retries=3, wait_duration_ms=1000, backoff_scaling=1.5))`.
- Entry point calls `app.start()`; deployed as a *Workflow* service with start command `python <entry>.py`.
- **No built-in scheduling.** A Render Cron Job triggers runs through the SDK client
  (`Render().workflows.start_task("<workflow-slug>/<task>", [...])`, needs `RENDER_API_KEY`).
- Local: `render workflows dev -- python <entry>.py` (CLI 2.12+, port 8120), point the SDK at it with `RENDER_TASKS_URL`.
