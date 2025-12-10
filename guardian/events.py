#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================================
 Project:    SecGuardian - Windows Host Intrusion Monitor
 File:       events.py
 Author:     Mobin Yousefi (GitHub: github.com/mobinyousefi-cs)
 Created:    2025-12-10
 Updated:    2025-12-10
 License:    MIT License (see LICENSE file for details)
 Description: Event model and event bus
===========================================================
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, Any, Optional
import queue
import time


class EventType(Enum):
    PROCESS = auto()
    NETWORK = auto()
    FILE = auto()
    REGISTRY = auto()
    GENERIC = auto()


class Severity(Enum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


@dataclass
class SecurityEvent:
    event_type: EventType
    severity: Severity
    message: str
    details: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    risk_score: float = 0.0


class EventBus:
    def __init__(self, event_queue: "queue.Queue[SecurityEvent]") -> None:
        self._queue = event_queue

    def publish(self, event: SecurityEvent) -> None:
        self._queue.put(event)
