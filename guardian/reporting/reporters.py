#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================================
 Project:    SecGuardian - Windows Host Intrusion Monitor
 File:       reporters.py.py
 Author:     Mobin Yousefi (GitHub: github.com/mobinyousefi-cs)
 Created:    2025-12-10
 Updated:    2025-12-10
 License:    MIT License (see LICENSE file for details)
 Description: Reporting modules: JSON, HTML, console alerts.
===========================================================
"""

import json
import logging
import time
from pathlib import Path
from dataclasses import asdict

from ..config import Config
from ..events import SecurityEvent


class BaseReporter:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)


class JSONReporter(BaseReporter):
    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.path = Path(config.log_dir) / "events.jsonl"

    def handle_event(self, event: SecurityEvent) -> None:
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(asdict(event), ensure_ascii=False) + "\n")
        except Exception as exc:
            self.logger.error(f"JSONReporter error: {exc}")


class HTMLReporter(BaseReporter):
    def __init__(self, config: Config) -> None:
        super().__init__(config)
        self.path = Path(config.log_dir) / "dashboard.html"

    def handle_event(self, event: SecurityEvent) -> None:
        # PoC: append simple table row
        try:
            if not self.path.exists():
                self._init_html()
            row = (
                f"<tr><td>{time.ctime(event.timestamp)}</td>"
                f"<td>{event.event_type.name}</td>"
                f"<td>{event.severity.name}</td>"
                f"<td>{event.risk_score:.1f}</td>"
                f"<td>{event.message}</td></tr>\n"
            )
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(row)
        except Exception as exc:
            self.logger.error(f"HTMLReporter error: {exc}")

    def _init_html(self) -> None:
        template = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>SecGuardian Dashboard</title>
<style>
body { font-family: sans-serif; }
table { border-collapse: collapse; width: 100%%; }
th, td { border: 1px solid #ccc; padding: 4px; font-size: 12px; }
th { background: #eee; }
</style>
</head>
<body>
<h1>SecGuardian Security Events</h1>
<table>
<thead>
<tr><th>Time</th><th>Type</th><th>Severity</th><th>Risk</th><th>Message</th></tr>
</thead>
<tbody>
"""
        with open(self.path, "w", encoding="utf-8") as f:
            f.write(template)


class ConsoleAlertReporter(BaseReporter):
    def handle_event(self, event: SecurityEvent) -> None:
        if event.risk_score >= self.config.risk_threshold_high:
            self.logger.warning(
                f"[ALERT] {event.event_type.name} {event.severity.name} "
                f"risk={event.risk_score:.1f} msg={event.message}"
            )
