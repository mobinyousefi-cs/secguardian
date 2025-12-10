#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================================
 Project:    SecGuardian - Windows Host Intrusion Monitor
 File:       risk.py
 Author:     Mobin Yousefi (GitHub: github.com/mobinyousefi-cs)
 Created:    2025-12-10
 Updated:    2025-12-10
 License:    MIT License (see LICENSE file for details)
 Description: Risk scoring engine
===========================================================
"""

from typing import Dict
from .events import SecurityEvent, EventType, Severity


class RiskEngine:
    """
    Very simple, configurable risk scoring engine.
    In a real system this would be more complex and data-driven.
    """

    BASE_SCORES: Dict[Severity, float] = {
        Severity.LOW: 10.0,
        Severity.MEDIUM: 40.0,
        Severity.HIGH: 70.0,
        Severity.CRITICAL: 90.0,
    }

    EVENT_TYPE_MULTIPLIER: Dict[EventType, float] = {
        EventType.PROCESS: 1.1,
        EventType.NETWORK: 1.2,
        EventType.FILE: 1.0,
        EventType.REGISTRY: 1.3,
        EventType.GENERIC: 1.0,
    }

    def calculate_risk(self, event: SecurityEvent) -> float:
        base = self.BASE_SCORES.get(event.severity, 10.0)
        mult = self.EVENT_TYPE_MULTIPLIER.get(event.event_type, 1.0)

        # add some simple feature-based tuning
        features = event.details
        suspicious_flags = 0

        for key in ("is_remote", "is_persistence", "is_encrypted", "is_injected"):
            if features.get(key, False):
                suspicious_flags += 1

        score = base * mult + suspicious_flags * 5.0
        return min(score, 100.0)
