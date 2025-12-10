#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================================
 Project:    SecGuardian - Windows Host Intrusion Monitor
 File:       yara_scanner.py
 Author:     Mobin Yousefi (GitHub: github.com/mobinyousefi-cs)
 Created:    2025-12-10
 Updated:    2025-12-10
 License:    MIT License (see LICENSE file for details)
 Description: YARA-based malware detection.
===========================================================
"""

import logging
from pathlib import Path
from typing import Optional

import yara

from ..config import Config
from ..events import SecurityEvent, EventType, Severity


class YaraScanner:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.logger = logging.getLogger(__name__)
        self._rules = self._load_rules()

    def _load_rules(self) -> Optional[yara.Rules]:
        path = Path(self.config.yara_rules_path)
        try:
            if path.is_dir():
                filepaths = {f"rule_{i}": str(p) for i, p in enumerate(path.glob("*.yar"))}
                return yara.compile(filepaths=filepaths)
            else:
                return yara.compile(filepath=str(path))
        except Exception as exc:
            self.logger.error(f"Failed to load YARA rules: {exc}")
            return None

    def maybe_scan_event(self, event: SecurityEvent) -> None:
        if not self._rules:
            return

        # PoC: اگر مسیر فایل یا exe در event بود، scan کن
        target_path = None
        if event.event_type == EventType.PROCESS:
            target_path = event.details.get("exe")
        elif event.event_type == EventType.FILE:
            target_path = event.details.get("path")

        if not target_path:
            return

        try:
            matches = self._rules.match(target_path)
            if matches:
                self.logger.warning(f"YARA match on {target_path}: {matches}")
                event.details["yara_matches"] = [m.rule for m in matches]
                event.severity = Severity.CRITICAL
        except Exception as exc:
            self.logger.error(f"YARA scan error for {target_path}: {exc}")
