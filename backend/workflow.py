"""Render Workflows entry point.

Deployed: Workflow service, build `pip install -r requirements.txt`, start `python workflow.py`.
Local with the Render CLI: `render workflows dev -- python workflow.py`.
Local without it: `python -m app.run_local` (same task code, in-process).
"""

from app.pipeline import app

if __name__ == "__main__":
    app.start()
