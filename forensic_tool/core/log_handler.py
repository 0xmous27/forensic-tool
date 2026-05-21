"""
core/log_handler.py

Custom logging handler that writes WARNING+ log records to the SystemLog
database table so they are visible in the system log viewer UI.
Uses a try/except guard to avoid recursion if the DB is unavailable.
"""

import logging


class DatabaseLogHandler(logging.Handler):
    """Persist WARNING and above log records to the SystemLog model."""

    def emit(self, record):
        # Only store WARNING, ERROR, CRITICAL + INFO for processing events
        if record.levelno < logging.INFO:
            return
        try:
            from core.models import SystemLog
            SystemLog.objects.create(
                level=record.levelname,
                module=record.module,
                message=self.format(record),
            )
        except Exception:
            # Never let logging errors crash the application
            pass
