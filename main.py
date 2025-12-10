#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
===========================================================
 Project:    SecGuardian - Windows Host Intrusion Monitor
 File:       main.py
 Author:     Mobin Yousefi (GitHub: github.com/mobinyousefi-cs)
 Created:    2025-12-10
 Updated:    2025-12-10
 License:    MIT License (see LICENSE file for details)
===========================================================

 Description:
    Entry point for the SecGuardian framework.
    Orchestrates configuration, monitoring, detection, forensic
    logging, and reporting.

 Usage:
    python main.py --rules ./rules/sample_rules.yar --log-dir ./logs

 Notes:
    - Requires Python 3.8+
    - Designed primarily for Windows 10/11
    - Many advanced features are PoC-level and need hardening
      before production use.

===========================================================
"""

import argparse
import logging
import threading
import queue
import time
from pathlib import Path

from guardian.config import Config
from guardian.events import SecurityEvent, EventBus
from guardian.risk import RiskEngine
from guardian.crypto_utils import SecureLogger
from guardian.adaptive import AdaptiveModel
from guardian.threat_intel import ThreatIntelClient

from guardian.monitoring.process_monitor import ProcessMonitor
from guardian.monitoring.network_monitor import NetworkMonitor
from guardian.monitoring.filesystem_monitor import FileSystemMonitor
from guardian.monitoring.registry_monitor import RegistryMonitor

from guardian.detection.yara_scanner import YaraScanner
from guardian.detection.heuristic_engine import HeuristicEngine
from guardian.detection.ransomware_detector import RansomwareDetector
from guardian.detection.behavior_analyzer import BehaviorAnalyzer

from guardian.forensic.collector import ForensicCollector
from guardian.reporting.reporters import (
    JSONReporter,
    HTMLReporter,
    ConsoleAlertReporter,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="SecGuardian - Host Intrusion Monitoring Framework"
    )
    parser.add_argument(
        "--rules", type=str, required=True, help="Path to YARA rules file or folder"
    )
    parser.add_argument(
        "--log-dir",
        type=str,
        default="./logs",
        help="Directory for encrypted forensic logs and reports",
    )
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug logging"
    )
    return parser.parse_args()


def setup_logging(debug: bool = False) -> None:
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )


def main() -> None:
    args = parse_args()
    setup_logging(args.debug)

    base_dir = Path(__file__).resolve().parent
    log_dir = base_dir / args.log_dir
    log_dir.mkdir(parents=True, exist_ok=True)

    config = Config(
        yara_rules_path=str(Path(args.rules).resolve()),
        log_dir=str(log_dir),
        risk_threshold_high=80.0,
        risk_threshold_medium=40.0,
        adaptive_model_path=str(log_dir / "adaptive_baseline.json"),
    )

    event_queue: "queue.Queue[SecurityEvent]" = queue.Queue()
    event_bus = EventBus(event_queue=event_queue)

    # Secure forensic logger (encrypted logs)
    secure_logger = SecureLogger(log_dir=config.log_dir)

    # Threat intel client (stubbed / PoC)
    ti_client = ThreatIntelClient()

    # Risk engine & adaptive model
    risk_engine = RiskEngine()
    adaptive_model = AdaptiveModel(config=config, logger=secure_logger)

    # Detection engines
    yara_scanner = YaraScanner(config=config)
    heuristic_engine = HeuristicEngine(config=config)
    ransomware_detector = RansomwareDetector(config=config)
    behavior_analyzer = BehaviorAnalyzer(config=config)

    forensic_collector = ForensicCollector(
        config=config, secure_logger=secure_logger
    )

    # Reporting modules
    json_reporter = JSONReporter(config=config)
    html_reporter = HTMLReporter(config=config)
    console_reporter = ConsoleAlertReporter(config=config)

    # Monitors
    process_monitor = ProcessMonitor(
        config=config, event_bus=event_bus, heuristic_engine=heuristic_engine
    )
    network_monitor = NetworkMonitor(
        config=config, event_bus=event_bus, ti_client=ti_client
    )
    filesystem_monitor = FileSystemMonitor(
        config=config, event_bus=event_bus
    )
    registry_monitor = RegistryMonitor(
        config=config, event_bus=event_bus
    )

    threads = [
        threading.Thread(target=process_monitor.run, daemon=True),
        threading.Thread(target=network_monitor.run, daemon=True),
        threading.Thread(target=filesystem_monitor.run, daemon=True),
        threading.Thread(target=registry_monitor.run, daemon=True),
    ]
    for t in threads:
        t.start()

    logging.info("SecGuardian started. Monitoring in progress...")

    try:
        while True:
            try:
                event = event_queue.get(timeout=1.0)
            except queue.Empty:
                # Periodically update adaptive model with benign baseline
                adaptive_model.update_baseline()
                continue

            # Compute risk score
            risk_score = risk_engine.calculate_risk(event)
            event.risk_score = risk_score

            # Forensic logging
            forensic_collector.record_event(event)

            # Reporting & alerts
            json_reporter.handle_event(event)
            html_reporter.handle_event(event)
            console_reporter.handle_event(event)

            # YARA / ransomware / behavioral checks can be triggered
            # selectively based on event type or risk.
            if risk_score >= config.risk_threshold_medium:
                yara_scanner.maybe_scan_event(event)
                ransomware_detector.analyze_event(event)
                behavior_analyzer.analyze_event(event)

    except KeyboardInterrupt:
        logging.info("SecGuardian shutting down gracefully...")


if __name__ == "__main__":
    main()
