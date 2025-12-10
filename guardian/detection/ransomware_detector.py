#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================================
 Project:    SecGuardian - Windows Host Intrusion Monitor
 File:       ransomware_detector.py
 Author:     Mobin Yousefi (GitHub: github.com/mobinyousefi-cs)
 Created:    2025-12-10
 Updated:    2025-12-10
 License:    MIT License (see LICENSE file for details)
 Description: Ransomware indicator detection (very simplified).
===========================================================
"""

import logging
from pathlib import Path

from ..config import Config
from ..events import SecurityEvent, EventType


class RansomwareDetector:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.logger = logging.getLogger(__name__)

    def analyze_event(self, event: SecurityEvent) -> None:
        if event.event_type != EventType.FILE:
            return

        path = Path(event.details.get("path", ""))
        # PoC: بررسی پسوندهای مشکوک
        suspicious_exts = [".locked", ".crypt", ".crypted", ".enc"]
        if any(str(path).lower().endswith(ext) for ext in suspicious_exts):
            event.details["ransomware_indicator"] = True
            # در عمل باید Timeline و زنجیره فایل‌ها بررسی شود
