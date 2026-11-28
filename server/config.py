"""Environment configuration and JSON-lines logging.

Reads the NEXUS_* variables once (documented in server/.env.example) into a small frozen
dataclass. This is process configuration, not a contract object.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone


@dataclass(frozen=True)
class Settings:
    db_url: str
    dashboard_token: str | None


def load_settings() -> Settings:
    """Read the environment. NEXUS_DB_URL is required and has no default."""
    db_url = os.environ.get("NEXUS_DB_URL", "").strip()
    if not db_url:
        raise RuntimeError("NEXUS_DB_URL is not set (see server/.env.example)")
    token = os.environ.get("NEXUS_DASHBOARD_TOKEN", "").strip() or None
    return Settings(db_url=db_url, dashboard_token=token)


class _JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        ts = datetime.fromtimestamp(record.created, tz=timezone.utc)
        out = {
            "ts": ts.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ts.microsecond // 1000:03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "fields", None)
        if isinstance(extra, dict):
            out.update(extra)
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)
        return json.dumps(out, default=str)


def setup_logging(level: str | None = None) -> None:
    """Configure the root logger to write one JSON object per line to stderr."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(_JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level or os.environ.get("NEXUS_LOG_LEVEL", "INFO"))
