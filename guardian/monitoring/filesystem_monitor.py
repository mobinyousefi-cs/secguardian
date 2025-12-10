#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================================
 Project:    SecGuardian - Windows Host Intrusion Monitor
 File:       filesystem_monitor.py
 Author:     Mobin Yousefi (GitHub: github.com/mobinyousefi-cs)
 Created:    2025-12-10
 Updated:    2025-12-10
 License:    MIT License (see LICENSE file for details)
 Description: Filesystem monitoring using watchdog.
 Note:
     You should expand critical paths (like Windows dir, user profile, startup folders) in Config.
===========================================================
"""

import logging
from pathlib import Path
from typing import List

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from ..config import Config
from ..events import EventBus, SecurityEvent, EventType, Severity


class _FSHandler(FileSystemEventHandler):
    def __init__(self, event_bus: EventBus, critical_paths: List[Path]) -> None:
        self.event_bus = event_bus
        self.critical_paths = critical_paths
        self.logger = logging.getLogger(__name__)

    def _is_critical(self, path: Path) -> bool:
        return any(str(path).startswith(str(cp)) for cp in self.critical_paths)

    def on_modified(self, event) -> None:
        path = Path(event.src_path)
        if self._is_critical(path):
            msg = f"Critical file modified: {path}"
            se = SecurityEvent(
                event_type=EventType.FILE,
                severity=Severity.HIGH,
                message=msg,
                details={"path": str(path)},
            )
            self.event_bus.publish(se)


class FileSystemMonitor:
    def __init__(self, config: Config, event_bus: EventBus) -> None:
        self.config = config
        self.event_bus = event_bus
        self.logger = logging.getLogger(__name__)
        self.observer = Observer()
        # PoC: فقط home directory و Startup
        home = Path.home()
        startup = Path.home() / "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup"
        self.critical_paths = [home, startup]

    def run(self) -> None:
        handler = _FSHandler(self.event_bus, self.critical_paths)
        for p in self.critical_paths:
            if p.exists():
                self.observer.schedule(handler, str(p), recursive=True)
        self.observer.start()
        self.logger.info("Filesystem monitor started.")
        try:
            while True:
                self.observer.join(timeout=1.0)
        except KeyboardInterrupt:
            self.observer.stop()
        self.observer.join()
