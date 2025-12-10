#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================================
 Project:    SecGuardian - Windows Host Intrusion Monitor
 File:       registry_monitor.py
 Author:     Mobin Yousefi (GitHub: github.com/mobinyousefi-cs)
 Created:    2025-12-10
 Updated:    2025-12-10
 License:    MIT License (see LICENSE file for details)
 Description: Windows Registry monitoring for autorun/persistence.
 Note:
     Real-time registry monitoring is difficult to do in Python and usually requires low-level APIs or WMI. 
     This module is a simple PoC that checks for autorun keys every few seconds.
===========================================================
"""

import logging
import time
from typing import List

from ..config import Config
from ..events import EventBus, SecurityEvent, EventType, Severity

try:
    import winreg  # type: ignore
except ImportError:  # Not on Windows
    winreg = None


class RegistryMonitor:
    AUTORUN_KEYS: List[str] = [
        r"Software\Microsoft\Windows\CurrentVersion\Run",
        r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    ]

    def __init__(
        self,
        config: Config,
        event_bus: EventBus,
        interval: float = 30.0,
    ) -> None:
        self.config = config
        self.event_bus = event_bus
        self.interval = interval
        self.logger = logging.getLogger(__name__)
        self._snapshot = {}

    def _snapshot_autorun(self) -> dict:
        if winreg is None:
            return {}
        snapshot = {}
        for key_path in self.AUTORUN_KEYS:
            try:
                with winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_READ
                ) as k:
                    i = 0
                    while True:
                        try:
                            name, value, _ = winreg.EnumValue(k, i)
                            snapshot[(key_path, name)] = value
                            i += 1
                        except OSError:
                            break
            except OSError:
                continue
        return snapshot

    def run(self) -> None:
        if winreg is None:
            self.logger.warning("RegistryMonitor disabled: winreg not available.")
            return
        self._snapshot = self._snapshot_autorun()
        while True:
            try:
                time.sleep(self.interval)
                new_snapshot = self._snapshot_autorun()
                for key, value in new_snapshot.items():
                    if key not in self._snapshot:
                        msg = f"New autorun entry detected: {key} -> {value}"
                        ev = SecurityEvent(
                            event_type=EventType.REGISTRY,
                            severity=Severity.HIGH,
                            message=msg,
                            details={
                                "key": key[0],
                                "name": key[1],
                                "value": value,
                                "is_persistence": True,
                            },
                        )
                        self.event_bus.publish(ev)
                self._snapshot = new_snapshot
            except Exception as exc:
                self.logger.error(f"RegistryMonitor error: {exc}")
