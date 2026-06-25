"""Celery app + scan task registration.

The scan task is the only thing the worker actually runs; all the real
work lives in orchestrator.run_scan_sync which is async internally but
called from a Celery task (using solo pool on Windows).
"""
from __future__ import annotations

import os

from celery import Celery
from celery.utils.log import get_task_logger

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
BROKER_URL = os.getenv("CELERY_BROKER_URL", REDIS_URL)
RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL)

celery_app = Celery(
    "kangal_worker",
    broker=BROKER_URL,
    backend=RESULT_BACKEND,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_track_started=True,
    broker_connection_retry_on_startup=True,
)

log = get_task_logger(__name__)


@celery_app.task(name="kangal.run_scan", bind=True, max_retries=1)
def run_scan_task(self, scan_id: str) -> dict:
    """Run the full recon pipeline for a scan_id."""
    log.info(f"Starting pipeline for scan {scan_id}")
    try:
        # Import locally so the worker doesn't pull orchestrator at import time
        from .orchestrator import run_scan_sync
        run_scan_sync(scan_id)
        return {"scan_id": scan_id, "status": "completed"}
    except Exception as e:
        log.exception(f"Scan {scan_id} failed: {e}")
        # mark scan as failed
        try:
            from .db import session_scope
            from .models import Scan
            from datetime import datetime
            for s in session_scope():
                sc = s.get(Scan, scan_id)
                if sc:
                    sc.status = "failed"
                    sc.error = str(e)[:1000]
                    sc.finished_at = datetime.utcnow()
        except Exception:
            pass
        raise
