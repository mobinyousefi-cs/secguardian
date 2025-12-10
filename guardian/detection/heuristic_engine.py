#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================================
 Project:    SecGuardian - Windows Host Intrusion Monitor
 File:       heuristic_engine.py
 Author:     Mobin Yousefi (GitHub: github.com/mobinyousefi-cs)
 Created:    2025-12-10
 Updated:    2025-12-10
 License:    MIT License (see LICENSE file for details)
 Description: Heuristic engine for suspicious processes/files.
===========================================================
"""

import logging
from typing import List

import psutil

from ..config import Config


SUSPICIOUS_NAMES: List[str] = [
    "mimikatz.exe",
    "psexec.exe",
    "nc.exe",
    "powershell.exe",  # context-dependent
]


class HeuristicEngine:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.logger = logging.getLogger(__name__)

    def score_process(self, proc: psutil.Process) -> float:
        score = 0.0
        info = proc.info
        name = (info.get("name") or "").lower()
        exe = (info.get("exe") or "").lower()
        cmd = " ".join(info.get("cmdline") or []).lower()

        if name in [n.lower() for n in SUSPICIOUS_NAMES]:
            score += 50.0

        if "powershell.exe" in name or "powershell" in cmd:
            if "encodedcommand" in cmd or "downloadstring" in cmd:
                score += 40.0

        # Fileless-ish pattern: process without valid exe path
        if not exe:
            score += 20.0

        # Suspicious parent (e.g., Office spawning powershell)
        try:
            ppid = info.get("ppid")
            if ppid:
                parent = psutil.Process(ppid)
                pname = (parent.name() or "").lower()
                if "winword.exe" in pname or "excel.exe" in pname:
                    if "powershell" in name:
                        score += 40.0
        except Exception:
            pass

        # Cap score
        return min(score, 100.0)
