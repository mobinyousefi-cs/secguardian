"""
===========================================================
 Project:    SecGuardian - Windows Host Intrusion Monitor
 File:       test_risk.py
 Author:     Mobin Yousefi (GitHub: github.com/mobinyousefi-cs)
 Created:    2025-12-10
 Updated:    2025-12-10
 License:    MIT License (see LICENSE file for details)
===========================================================
"""
import pytest
from guardian.risk import RiskEngine
from guardian.events import SecurityEvent, EventType, Severity


def test_risk_basic_scoring():
    engine = RiskEngine()
    ev = SecurityEvent(
        event_type=EventType.PROCESS,
        severity=Severity.MEDIUM,
        message="test",
        details={"is_persistence": True},
    )
    score = engine.calculate_risk(ev)
    assert 40.0 <= score <= 100.0
