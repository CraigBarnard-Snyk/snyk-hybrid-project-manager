"""Run logging: a human-readable .log plus a machine-readable .jsonl."""

from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

LOG_FORMAT = "%(asctime)s %(levelname)-7s %(message)s"
DATE_FORMAT = "%Y-%m-%dT%H:%M:%S%z"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def run_id_for(moment: datetime) -> str:
    return moment.strftime("%Y%m%dT%H%M%SZ")


class Reporter:
    """Writes the run's .log and .jsonl, mirroring the text log to stdout.

    The JSONL file records one object per decision, so a dry run can be diffed
    or audited before anything is deleted.
    """

    def __init__(
        self,
        log_dir: str | Path,
        dry_run: bool,
        run_id: str | None = None,
        verbose: bool = False,
    ):
        started = utc_now()
        self.run_id = run_id or run_id_for(started)
        self.dry_run = dry_run
        self.started_at = started

        directory = Path(log_dir).expanduser()
        directory.mkdir(parents=True, exist_ok=True)
        self.text_path = directory / f"run-{self.run_id}.log"
        self.jsonl_path = directory / f"run-{self.run_id}.jsonl"

        self.log = logging.getLogger("snyk_hybrid_project_manager")
        self.log.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.log.handlers.clear()
        self.log.propagate = False

        formatter = logging.Formatter(LOG_FORMAT, DATE_FORMAT)

        file_handler = logging.FileHandler(self.text_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        self.log.addHandler(file_handler)

        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setFormatter(formatter)
        stream_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
        self.log.addHandler(stream_handler)

        # The API client logs retries through its own module logger.
        api_logger = logging.getLogger("snyk_hybrid_project_manager.api")
        api_logger.setLevel(logging.DEBUG if verbose else logging.INFO)

        self._jsonl = self.jsonl_path.open("w", encoding="utf-8")

    def event(self, event: str, **fields: Any) -> None:
        record = {
            "ts": utc_now().isoformat(),
            "run_id": self.run_id,
            "dry_run": self.dry_run,
            "event": event,
        }
        record.update(fields)
        self._jsonl.write(json.dumps(record, default=str, sort_keys=False) + "\n")
        self._jsonl.flush()

    def close(self) -> None:
        try:
            self._jsonl.close()
        finally:
            for handler in list(self.log.handlers):
                handler.flush()
                if isinstance(handler, logging.FileHandler):
                    handler.close()
                self.log.removeHandler(handler)

    def __enter__(self) -> "Reporter":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
