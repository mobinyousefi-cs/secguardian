#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================================
 Project:    SecGuardian - Windows Host Intrusion Monitor
 File:       config.py
 Author:     Mobin Yousefi (GitHub: github.com/mobinyousefi-cs)
 Created:    2025-12-10
 Updated:    2025-12-10
 License:    MIT License (see LICENSE file for details)
 Description: Config module for SecGuardian
===========================================================
"""

from dataclasses import dataclass


@dataclass
class Config:
    yara_rules_path: str
    log_dir: str
    risk_threshold_high: float = 80.0
    risk_threshold_medium: float = 40.0
    adaptive_model_path: str = "./adaptive_baseline.json"
