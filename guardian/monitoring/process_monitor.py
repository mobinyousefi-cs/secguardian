#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================================
 Project:    SecGuardian - Windows Host Intrusion Monitor
 File:       process_monitor.py
 Author:     Mobin Yousefi (GitHub: github.com/mobinyousefi-cs)
 Created:    2025-12-10
 Updated:    2025-12-10
 License:    MIT License (see LICENSE file for details)
 Description: 
        Real-time process monitoring.
        Detects suspicious patterns (very basic PoC).
===========================================================
"""

import logging
import time
from typing import Dict, Any

import psutil

from ..config import Config
from ..events import EventBus, SecurityEvent, EventType, Severity
from ..detection.heuristic_engine import HeuristicEngine


class ProcessMonitor:
    def __init__(
        self,
        config: Config,
        event_bus: EventBus,
        heuristic_engine: HeuristicEngine,
        interval: float = 5.0,
    ) -> None:
        self.config = config
        self.event_bus = event_bus
        self.heuristic_engine = heuristic_engine
        self.interval = interval
        self.logger = logging.getLogger(__name__)
        self._known_pids = set()

    def _build_event_from_proc(self, proc: psutil.Process, score: float) -> SecurityEvent:
        details: Dict[str, Any] = {
            "pid": proc.pid,
            "name": proc.info.get("name"),
            "exe": proc.info.get("exe"),
            "cmdline": proc.info.get("cmdline"),
            "username": proc.info.get("username"),
            "is_injected": score >= 70.0,  # heuristic flag
        }
        severity = Severity.MEDIUM if score < 70 else Severity.HIGH
        msg = f"Suspicious process detected: {details['name']} (PID={proc.pid})"
        return SecurityEvent(
            event_type=EventType.PROCESS,
            severity=severity,
            message=msg,
            details=details,
        )

    def run(self) -> None:
        while True:
            try:
                for proc in psutil.process_iter(
                    attrs=["pid", "name", "exe", "cmdline", "username", "ppid"]
                ):
                    if proc.pid not in self._known_pids:
                        self._known_pids.add(proc.pid)
                        # Simple heuristic analysis
                        score = self.heuristic_engine.score_process(proc)
                        if score >= 50.0:
                            event = self._build_event_from_proc(proc, score)
                            self.event_bus.publish(event)
                time.sleep(self.interval)
            except Exception as exc:
                self.logger.error(f"Process monitor error: {exc}")
                time.sleep(self.interval)
