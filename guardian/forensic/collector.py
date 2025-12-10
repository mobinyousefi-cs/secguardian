#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================================
 Project:    SecGuardian - Windows Host Intrusion Monitor
 File:       collector.py
 Author:     Mobin Yousefi (GitHub: github.com/mobinyousefi-cs)
 Created:    2025-12-10
 Updated:    2025-12-10
 License:    MIT License (see LICENSE file for details)
 Description: Forensic collector: central point for evidence collection & timeline.
===========================================================
"""

import logging
from dataclasses import asdict

from ..config import Config
from ..crypto_utils import SecureLogger
from ..events import SecurityEvent


class ForensicCollector:
    def __init__(self, config: Config, secure_logger: SecureLogger) -> None:
        self.config = config
        self.sec_logger = secure_logger
        self.logger = logging.getLogger(__name__)

    def record_event(self, event: SecurityEvent) -> None:
        try:
            self.sec_logger.log_event(asdict(event))
        except Exception as exc:
            self.logger.error(f"Failed to record forensic event: {exc}")
