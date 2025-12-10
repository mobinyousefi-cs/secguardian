#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================================
 Project:    SecGuardian - Windows Host Intrusion Monitor
 File:       crypto_utils.py
 Author:     Mobin Yousefi (GitHub: github.com/mobinyousefi-cs)
 Created:    2025-12-10
 Updated:    2025-12-10
 License:    MIT License (see LICENSE file for details)
 Description: Secure logging utilities.
 Note:
    For simplicity, 
    hashlib + XOR-style pseudo-encryption is used here to minimize dependency on crypto libraries. 
    In a real environment, 
    a library like cryptography (AES-GCM) should be used.
===========================================================
"""

import json
import os
import hashlib
import logging
import platform
from pathlib import Path
from typing import Any, Dict
from enum import Enum


class EnumJSONEncoder(json.JSONEncoder):
    """
    Custom JSON encoder that knows how to serialize Enum objects.
    """

    def default(self, o: Any) -> Any:
        if isinstance(o, Enum):
            return o.name
        return super().default(o)


class SecureLogger:
    def __init__(self, log_dir: str) -> None:
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self._key = self._derive_key()

    def _derive_key(self) -> bytes:
        """
        Generate a simple key from environment variable or hostname.
        platform.node() is cross-platform (Windows/Linux/macOS).
        """
        seed = os.environ.get("SECGUARDIAN_KEY", platform.node())
        return hashlib.sha256(seed.encode("utf-8")).digest()

    def _encrypt(self, data: bytes) -> bytes:
        """
        Very basic XOR encryption (PoC only).
        """
        key = self._key
        return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

    def log_event(self, event: Dict[str, Any]) -> None:
        """
        Securely log a forensic event.
        'event' is expected to be a dict, possibly containing Enum values.
        """
        try:
            raw = json.dumps(
                event,
                ensure_ascii=False,
                cls=EnumJSONEncoder,  # <-- این مهم است
            ).encode("utf-8")
            enc = self._encrypt(raw)
            fname = self.log_dir / "forensic.log.enc"
            with open(fname, "ab") as f:
                f.write(enc + b"\n")
        except Exception as exc:
            logging.getLogger(__name__).error(
                f"Failed to log event securely: {exc}"
            )