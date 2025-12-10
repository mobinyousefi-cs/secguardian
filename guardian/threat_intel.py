#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================================
 Project:    SecGuardian - Windows Host Intrusion Monitor
 File:       threat_intel.py
 Author:     Mobin Yousefi (GitHub: github.com/mobinyousefi-cs)
 Created:    2025-12-10
 Updated:    2025-12-10
 License:    MIT License (see LICENSE file for details)
 Description: 
        Threat intelligence client (stub).
        In real deployments this would query external or internal
        TI platforms (MISP, Virustotal, OpenCTI, etc.).
===========================================================
"""

import logging
from typing import Optional


class ThreatIntelClient:
    def __init__(self) -> None:
        self.logger = logging.getLogger(__name__)

    def is_malicious_ip(self, ip: str) -> Optional[bool]:
        """
        Return:
            True  => known malicious
            False => known benign
            None  => unknown
        Currently a stub that returns None.
        """
        # TODO: integrate with real TI feeds / local DB
        self.logger.debug(f"TI lookup for IP={ip}")
        return None
