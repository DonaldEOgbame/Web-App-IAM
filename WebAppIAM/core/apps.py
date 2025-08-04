# core/apps.py
import os
import threading
import time
import logging
from django.apps import AppConfig
from django.conf import settings

logger = logging.getLogger(__name__)


class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core"

    # Process-wide guard against duplicate ready() work
    _ready_done = False

    def ready(self):
        # Ensure signal registration (idempotent)
        try:
            import core.signals  # noqa: F401
        except Exception as e:
            logger.warning("core.signals import failed (non-fatal): %s", e)

        # Prevent double execution (esp. with gunicorn workers or reloader)
        if CoreConfig._ready_done:
            return
        CoreConfig._ready_done = True

        # In DEBUG, avoid running in the autoreloader's parent process
        if settings.DEBUG and os.environ.get("RUN_MAIN") not in {"true", "1"}:
            logger.debug("CoreConfig.ready(): skipped in autoreloader parent process.")
            return

        # Allow opt-out: set SKIP_WARMUP=1 to bypass all warmups
        if os.environ.get("SKIP_WARMUP") in {"1", "true", "True"}:
            logger.info("Warmup skipped due to SKIP_WARMUP env var.")
            return

        def _warmup():
            start_all = time.perf_counter()
            # Risk engine warmup
            try:
                from .risk_engine import warmup as risk_warmup
                t0 = time.perf_counter()
                risk_warmup()
                logger.info("risk_engine.warmup() completed in %.2fs", time.perf_counter() - t0)
            except Exception as e:
                logger.exception("risk_engine.warmup() failed: %s", e)

            # Face API warmup (loads DeepFace backbone once)
            try:
                from .face_api import warmup as face_warmup
                t1 = time.perf_counter()
                face_warmup()
                logger.info("face_api.warmup() completed in %.2fs", time.perf_counter() - t1)
            except Exception as e:
                logger.exception("face_api.warmup() failed: %s", e)

            logger.info("All warmups finished in %.2fs", time.perf_counter() - start_all)

        # In dev, warm up asynchronously so the server starts quickly
        if settings.DEBUG:
            threading.Thread(target=_warmup, daemon=True, name="core-warmup").start()
            logger.debug("Warmup thread started (DEBUG mode).")
        else:
            # In production, run synchronously to keep first request fast
            _warmup()
