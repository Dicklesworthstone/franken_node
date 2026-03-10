"""Shared test-logging framework for verification scripts.

Provides ``configure_test_logging(script_name)`` which wires up:
  * Structured JSON or human-readable log lines to **stderr**.
  * Rotating log files under ``logs/verification/`` (one file per script).

Usage::

    from scripts.lib.test_logger import configure_test_logging
    logger = configure_test_logging("check_proof_generator")
    logger.info("starting verification", extra={"check_count": 12})

The returned logger is a stdlib ``logging.Logger`` decorated with a JSON
formatter when ``--json`` is present in ``sys.argv``.  Human-readable mode
uses a concise ``%(levelname)s %(name)s: %(message)s`` format.

Log-file rotation keeps the 5 most recent runs (1 MiB each).
"""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any

__all__ = ["configure_test_logging"]

# ── Constants ────────────────────────────────────────────────────────────

_ROOT = Path(__file__).resolve().parent.parent.parent
_LOG_DIR = _ROOT / "logs" / "verification"
_MAX_BYTES = 1 * 1024 * 1024  # 1 MiB per file
_BACKUP_COUNT = 5


# ── JSON Formatter ───────────────────────────────────────────────────────

class _JsonFormatter(logging.Formatter):
    """Emits each log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        # Merge caller-supplied extras (skip internal fields).
        for key, value in record.__dict__.items():
            if key.startswith("_") or key in (
                "name", "msg", "args", "created", "relativeCreated",
                "exc_info", "exc_text", "stack_info", "lineno", "funcName",
                "pathname", "filename", "module", "levelno", "levelname",
                "msecs", "thread", "threadName", "processName", "process",
                "message", "taskName",
            ):
                continue
            payload[key] = value
        return json.dumps(payload, default=str)


class _HumanFormatter(logging.Formatter):
    """Concise single-line format for interactive use."""

    def __init__(self) -> None:
        super().__init__("%(levelname)-5s %(name)s: %(message)s")


# ── Public API ───────────────────────────────────────────────────────────

def configure_test_logging(
    script_name: str,
    *,
    level: int = logging.DEBUG,
    json_mode: bool | None = None,
) -> logging.Logger:
    """Set up and return a logger for *script_name*.

    Parameters
    ----------
    script_name:
        Used as the logger name and the log-file stem
        (e.g. ``"check_proof_generator"``).
    level:
        Minimum logging level.  Defaults to ``DEBUG``.
    json_mode:
        Force JSON output.  When ``None`` (the default), JSON mode is
        auto-detected from ``--json`` in ``sys.argv``.

    Returns
    -------
    logging.Logger
        A fully-configured logger.
    """
    if json_mode is None:
        json_mode = "--json" in sys.argv

    logger = logging.getLogger(script_name)
    logger.setLevel(level)

    # Avoid duplicate handlers on repeated calls (e.g. in tests).
    if logger.handlers:
        return logger

    formatter: logging.Formatter = (
        _JsonFormatter() if json_mode else _HumanFormatter()
    )

    # 1. stderr handler
    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(level)
    stderr_handler.setFormatter(formatter)
    logger.addHandler(stderr_handler)

    # 2. Rotating file handler (best-effort — skip if dir is unwritable).
    try:
        _LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_path = _LOG_DIR / f"{script_name}.log"
        file_handler = RotatingFileHandler(
            log_path,
            maxBytes=_MAX_BYTES,
            backupCount=_BACKUP_COUNT,
            encoding="utf-8",
        )
        file_handler.setLevel(level)
        file_handler.setFormatter(_JsonFormatter())  # always JSON on disk
        logger.addHandler(file_handler)
    except OSError:
        # Non-fatal: logging to file is optional.
        pass

    # Prevent propagation to root logger (avoids duplicate output).
    logger.propagate = False

    return logger


# ── Self-test ────────────────────────────────────────────────────────────

def self_test() -> None:
    """Minimal smoke-test invoked by ``python -m scripts.lib.test_logger``."""
    log = configure_test_logging("test_logger_selftest", json_mode=False)
    log.info("human-mode line")
    log.debug("debug detail", extra={"key": "value"})

    log2 = configure_test_logging("test_logger_selftest_json", json_mode=True)
    log2.info("json-mode line", extra={"count": 42})

    # Verify idempotency — second call must not add duplicate handlers.
    log3 = configure_test_logging("test_logger_selftest")
    assert len(log3.handlers) == len(log.handlers), "handler count changed on re-init"

    print("self_test PASSED")


if __name__ == "__main__":
    self_test()
