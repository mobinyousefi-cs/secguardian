"""
===========================================================
 Project:    SecGuardian - Windows Host Intrusion Monitor
 File:       test_yara_scanner.py
 Author:     Mobin Yousefi (GitHub: github.com/mobinyousefi-cs)
 Created:    2025-12-10
 Updated:    2025-12-10
 License:    MIT License (see LICENSE file for details)
===========================================================
"""
from guardian.detection.yara_scanner import YaraScanner
from guardian.config import Config
from guardian.events import SecurityEvent, EventType, Severity


def test_yara_scanner_loads_rules():
    cfg = Config(yara_rules_path="./rules/sample_rules.yar", log_dir="./logs")
    scanner = YaraScanner(cfg)
    assert scanner._rules is not None


def test_yara_scanner_no_crash_without_target():
    cfg = Config(yara_rules_path="./rules/sample_rules.yar", log_dir="./logs")
    scanner = YaraScanner(cfg)
    ev = SecurityEvent(
        event_type=EventType.GENERIC,
        severity=Severity.LOW,
        message="no target",
        details={},
    )
    scanner.maybe_scan_event(ev)  # should not raise
