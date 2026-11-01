"""Run the Workflows pipeline in-process, no Render CLI or account needed.

    python -m app.run_local                  # one pull since the stored cursor, then enrich
    python -m app.run_local --enrich-only    # KEV, patch status, NVD on what's stored
    python -m app.run_local --every 900      # demo mode: pull every 15 minutes
    python -m app.run_local --since 2026-11-01T00:00:00.000Z   # replay a window (dedup test)

LocalContext implements the same TaskContext protocol Render passes in, so the task code that
runs here is exactly the code that runs on Render.
"""

import argparse
import asyncio
import inspect
import json
import time

from render.workflows.task import TaskDefinition

from .pipeline import enrich_cves, ingest_cves, refresh


class LocalContext:
    async def run(self, task: TaskDefinition, *args, **kwargs):
        if inspect.iscoroutinefunction(task.func):
            return await task.func(self, *args, **kwargs)
        return await asyncio.to_thread(task.func, self, *args, **kwargs)


def run_once(since: str | None = None) -> dict:
    """Ingest only (Phase 1 behaviour, used by tests)."""
    return asyncio.run(LocalContext().run(ingest_cves, since))


def run_refresh(since: str | None = None, enrich_only: bool = False) -> dict:
    if enrich_only:
        return asyncio.run(LocalContext().run(enrich_cves))
    return asyncio.run(LocalContext().run(refresh, since))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--since", help="ignore the cursor and replay from this ISO timestamp")
    parser.add_argument("--every", type=int, help="repeat every N seconds")
    parser.add_argument("--enrich-only", action="store_true", help="skip the feed pull, just enrich")
    args = parser.parse_args()

    while True:
        t0 = time.monotonic()
        result = run_refresh(args.since, args.enrich_only)
        print(json.dumps({**result, "seconds": round(time.monotonic() - t0, 1)}), flush=True)
        if not args.every:
            break
        args.since = None
        time.sleep(args.every)


if __name__ == "__main__":
    main()
