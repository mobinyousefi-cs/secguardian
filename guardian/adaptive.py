#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================================
 Project:    SecGuardian - Windows Host Intrusion Monitor
 File:       adaptive.py
 Author:     Mobin Yousefi (GitHub: github.com/mobinyousefi-cs)
 Created:    2025-12-10
 Updated:    2025-12-10
 License:    MIT License (see LICENSE file for details)
 Description: 
        Adaptive baseline model (very simple PoC).
        Learns rough baseline of process count & network connections.
===========================================================
"""

import json
import logging
from pathlib import Path
from typing import Dict

import psutil

from .config import Config
from .crypto_utils import SecureLogger


class AdaptiveModel:
    def __init__(self, config: Config, logger: SecureLogger) -> None:
        self.config = config
        self.sec_logger = logger
        self._baseline_path = Path(config.adaptive_model_path)
        self._baseline: Dict[str, float] = self._load_baseline()

    def _load_baseline(self) -> Dict[str, float]:
        if self._baseline_path.exists():
            try:
                with open(self._baseline_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as exc:
                logging.getLogger(__name__).error(f"Failed to load baseline: {exc}")
        return {"avg_processes": 0.0, "avg_connections": 0.0, "samples": 0.0}

    def _save_baseline(self) -> None:
        try:
            with open(self._baseline_path, "w", encoding="utf-8") as f:
                json.dump(self._baseline, f, indent=2)
        except Exception as exc:
            logging.getLogger(__name__).error(f"Failed to save baseline: {exc}")

    def update_baseline(self) -> None:
        """
        Called periodically in main loop when no high-risk events occurred.
        """
        try:
            proc_count = len(list(psutil.process_iter()))
            conn_count = len(psutil.net_connections())
        except Exception as exc:
            logging.getLogger(__name__).error(f"Failed to sample system for baseline: {exc}")
            return

        b = self._baseline
        n = b["samples"] + 1.0
        b["avg_processes"] = (b["avg_processes"] * b["samples"] + proc_count) / n
        b["avg_connections"] = (b["avg_connections"] * b["samples"] + conn_count) / n
        b["samples"] = n
        self._save_baseline()
