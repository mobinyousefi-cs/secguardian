"""
===========================================================
 Project:    SecGuardian - Windows Host Intrusion Monitor
 File:       test_heuristic_engine.py
 Author:     Mobin Yousefi (GitHub: github.com/mobinyousefi-cs)
 Created:    2025-12-10
 Updated:    2025-12-10
 License:    MIT License (see LICENSE file for details)
===========================================================
"""
import psutil
from guardian.detection.heuristic_engine import HeuristicEngine
from guardian.config import Config


class DummyProc:
    def __init__(self):
        self.info = {
            "pid": 1234,
            "name": "powershell.exe",
            "exe": "",
            "cmdline": ["powershell.exe", "-EncodedCommand", "AAA"],
            "ppid": None,
        }


def test_heuristic_scores_powershell_encoded():
    cfg = Config(yara_rules_path="./rules/sample_rules.yar", log_dir="./logs")
    engine = HeuristicEngine(cfg)
    proc = DummyProc()
    score = engine.score_process(proc)  # type: ignore[arg-type]
    assert score >= 40.0
