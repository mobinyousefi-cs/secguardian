#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================================
 Project:    SecGuardian - Windows Host Intrusion Monitor
 File:       network_monitor.py
 Author:     Mobin Yousefi (GitHub: github.com/mobinyousefi-cs)
 Created:    2025-12-10
 Updated:    2025-12-10
 License:    MIT License (see LICENSE file for details)
 Description: Network monitoring (psutil-based, plus optional scapy sniff).
===========================================================
"""

import logging
import time
from typing import Dict, Any

import psutil

from ..config import Config
from ..events import EventBus, SecurityEvent, EventType, Severity
from ..threat_intel import ThreatIntelClient


class NetworkMonitor:
    def __init__(
        self,
        config: Config,
        event_bus: EventBus,
        ti_client: ThreatIntelClient,
        interval: float = 5.0,
    ) -> None:
        self.config = config
        self.event_bus = event_bus
        self.interval = interval
        self.ti_client = ti_client
        self.logger = logging.getLogger(__name__)
        self._seen = set()

    def _build_event(self, conn: psutil._common.sconn) -> SecurityEvent:
        laddr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "?:?"
        raddr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "?:?"
        details: Dict[str, Any] = {
            "laddr": laddr,
            "raddr": raddr,
            "status": conn.status,
            "pid": conn.pid,
            "is_remote": bool(conn.raddr),
        }

        severity = Severity.MEDIUM
        msg = f"Suspicious network connection {laddr} -> {raddr} ({conn.status})"
        return SecurityEvent(
            event_type=EventType.NETWORK,
            severity=severity,
            message=msg,
            details=details,
        )

    def run(self) -> None:
        while True:
            try:
                conns = psutil.net_connections(kind="inet")
                for c in conns:
                    key = (c.laddr, c.raddr, c.status, c.pid)
                    if key in self._seen:
                        continue
                    self._seen.add(key)

                    if not c.raddr:
                        continue  # local only

                    ip = c.raddr.ip
                    ti = self.ti_client.is_malicious_ip(ip)
                    # اگر TI چیزی نگفت، با Heuristic ساده بررسی کن
                    if ti is True or c.raddr.port in (4444, 1337, 8081):
                        event = self._build_event(c)
                        if ti is True:
                            event.details["ti_malicious_ip"] = ip
                        self.event_bus.publish(event)

                time.sleep(self.interval)
            except Exception as exc:
                self.logger.error(f"Network monitor error: {exc}")
                time.sleep(self.interval)
