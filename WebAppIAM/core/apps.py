# core/apps.py
import os
import threading
from django.apps import AppConfig
from django.conf import settings

class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "core"
    _ready_done = False

    def ready(self):
        import core.signals  # noqa: F401
        if CoreConfig._ready_done:
            return
        CoreConfig._ready_done = True
        if settings.DEBUG and os.environ.get("RUN_MAIN") not in {"true", "1"}:
            return

        def _warmup():
            try:
                from .risk_engine import warmup
                warmup()
            except Exception:
                pass

        if settings.DEBUG:
            threading.Thread(target=_warmup, daemon=True).start()
        else:
            _warmup()
