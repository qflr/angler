"""Cron Job entry point: start one `refresh` run of the pipeline workflow.

Workflows has no built-in scheduler, so a Render Cron Job runs this every 15 minutes.
Needs RENDER_API_KEY. The task slug is <workflow service slug>/<task name>.
"""

import os
from datetime import datetime, timezone

from render import Render

SLUG = f"{os.getenv('ANGLER_WORKFLOW_SLUG', 'angler-pipeline')}/refresh"

if __name__ == "__main__":
    # Same key for the same 15-minute slot, so a retried cron run can't start a second refresh.
    now = datetime.now(timezone.utc)
    slot = now.strftime("%Y%m%d%H") + f"{now.minute // 15:02d}"
    run = Render().workflows.start_task(SLUG, [], idempotency_key=f"refresh-{slot}")
    print(f"started {SLUG}: {run.id}")
