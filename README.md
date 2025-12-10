# SecGuardian – Windows Host Intrusion Monitoring Framework

SecGuardian is a **research‑oriented, host‑based intrusion monitoring framework** written in Python.
It is designed primarily for **Windows 10/11** and focuses on:

* Real‑time monitoring of **processes, network activity, file system, and registry**
* **YARA‑based** malware detection
* Simple **heuristic and behavioral analysis** for suspicious activity
* Detection of basic **ransomware indicators**
* **Forensic logging** with encrypted logs
* **Risk scoring** and lightweight reporting (JSON/HTML/console)
* A minimal **adaptive learning** component to model the baseline of the host

> ⚠️ **Disclaimer**
> SecGuardian is a **Proof of Concept (PoC)** for research, education, and lab use only.
> It is **not** a replacement for commercial EDR/AV products and should **not** be used as the only security control in production systems.

---

## 1. Features & Capabilities

### 1.1 Real‑Time Monitoring

1. **Process Monitoring** (`guardian/monitoring/process_monitor.py`)

   * Uses `psutil` to enumerate running processes.
   * Detects new processes and scores them using the **Heuristic Engine**.
   * Flags suspicious processes, such as:

     * PowerShell with `-EncodedCommand`
     * Processes without a valid executable path (fileless‑like behavior)
     * Suspicious parent/child relations (e.g., Office → PowerShell)

2. **Network Monitoring** (`guardian/monitoring/network_monitor.py`)

   * Uses `psutil.net_connections()` to inspect network connections.
   * Flags suspicious connections based on:

     * Unusual remote ports (e.g., 4444, 1337, 8081 – common in C2 labs)
     * Potential matches from **Threat Intelligence** (stubbed for PoC).

3. **File System Monitoring** (`guardian/monitoring/filesystem_monitor.py`)

   * Uses `watchdog` to monitor **critical paths** (by default: user profile & Startup folder).
   * Raises events on modifications to critical files.

4. **Registry Monitoring (Windows)** (`guardian/monitoring/registry_monitor.py`)

   * Uses `winreg` (only available on Windows).
   * Periodically snapshots standard **autorun keys** such as:

     * `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
     * `HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce`
   * Detects new persistence entries and flags them as high‑risk events.

---

### 1.2 Malware Detection

1. **YARA‑Based Detection** (`guardian/detection/yara_scanner.py`)

   * Loads rules from a **file or folder** specified via `--rules`.
   * On suspicious events (medium+ risk), may scan:

     * Executable paths of processes
     * Paths of modified files
   * Matches are attached to events as metadata and can raise severity.

2. **Heuristic Engine** (`guardian/detection/heuristic_engine.py`)

   * Assigns a **score (0–100)** to processes based on:

     * Process name and executable path
     * Command‑line arguments
     * Parent process (for simple correlation)
   * Special focus on:

     * `powershell.exe` with encoded commands
     * processes spawned from Office applications
     * processes without a valid executable path (fileless patterns)

3. **Ransomware Indicators** (`guardian/detection/ransomware_detector.py`)

   * Looks for files with **suspicious extensions** (e.g., `.locked`, `.crypt`, `.crypted`, `.enc`).
   * Designed as a **hook point**: in a real system you would correlate this with:

     * High IO write bursts
     * File rename storms
     * Shadow copy deletion, etc.

4. **Behavioral Analyzer (Stub)** (`guardian/detection/behavior_analyzer.py`)

   * Placeholder for **multi‑event correlation**:

     * Lateral movement patterns
     * Privilege escalation sequences
     * Attack chains (process → network → file → registry)
   * Currently logs debug messages; intended as a starting point for more complex research.

---

### 1.3 Network Analysis

* Inspects active TCP/UDP connections via `psutil`.
* Provides a hook for a **Threat Intelligence client** (`guardian/threat_intel.py`):

  * Currently a stub, returns `None` (unknown) for all IPs.
  * In a real deployment, plug this into:

    * MISP, OpenCTI, VirusTotal, commercial TI platforms, or local blacklist DB.
* Flags suspicious connections based on:

  * Remote IP reputation (when integrated)
  * Ports often associated with C2 or reverse shells.

---

### 1.4 Forensic Module

1. **Evidence Collection** (`guardian/forensic/collector.py`)

   * Centralizes event collection.
   * Serializes each `SecurityEvent` and passes it to a **Secure Logger**.

2. **Secure Logger** (`guardian/crypto_utils.py`)

   * Stores encrypted log lines in `forensic.log.enc`.
   * Uses a simple **XOR‑based scheme** derived from a key:

     * `SECGUARDIAN_KEY` environment variable (if set), otherwise hostname.
   * This is **not cryptographically secure** and is used only to:

     * Prevent casual tampering/inspection in PoC scenarios.
   * For real deployments, replace with a robust cipher (e.g., AES‑GCM using `cryptography` library).

3. **Timeline & Analysis (Future Work)**

   * All events are timestamped and can be post‑processed into a **timeline** of incidents.
   * You can build separate Jupyter notebooks or scripts to:

     * Parse `events.jsonl` and `forensic.log.enc`
     * Build incident timelines and graphs.

---

### 1.5 Reporting Module

1. **JSON Reporter** (`guardian/reporting/reporters.py` – `JSONReporter`)

   * Streams all events into `events.jsonl` (JSON Lines format).
   * Useful for:

     * Log aggregation
     * Feeding SIEM/splunk/ELK stack
     * Post‑incident analysis.

2. **HTML Reporter / Dashboard** (`HTMLReporter`)

   * Creates/updates `dashboard.html` inside the log directory.
   * Maintains a simple table of events:

     * Time, type, severity, risk, message.
   * Can be opened in a browser for a quick overview.

3. **Console Alert Reporter** (`ConsoleAlertReporter`)

   * Prints **high‑risk events** to console using Python logging.
   * Threshold controlled with `Config.risk_threshold_high`.

---

### 1.6 Risk Scoring System

Implemented in `guardian/risk.py`.

* Base score based on **Severity** (LOW/MEDIUM/HIGH/CRITICAL).
* Multipliers based on **Event Type** (PROCESS/NETWORK/FILE/REGISTRY/GENERIC).
* Additional points for certain flags in `event.details`, such as:

  * `is_remote`
  * `is_persistence`
  * `is_encrypted`
  * `is_injected`
* Score range is clamped to **0–100**.

This is intentionally simple but structured, so you can:

* Evolve it into a **data‑driven model**.
* Train/fit parameters on labeled datasets of benign vs malicious events.

---

### 1.7 Adaptive Learning (Baseline Modeling)

`guardian/adaptive.py` implements a minimal **baseline model**:

* Periodically samples:

  * Number of processes
  * Number of network connections
* Maintains running averages:

  * `avg_processes`
  * `avg_connections`
  * `samples`
* Stores data as JSON (`adaptive_baseline.json`).

Use cases:

* Compare current system state against historical baseline.
* Detect anomalies such as:

  * Sudden spikes in process count (e.g., process injection storms).
  * Sudden spikes in network connections.

> Note: This is intentionally simplistic. In a real research project, you could replace this with an **unsupervised anomaly detector** (e.g., Isolation Forest, One‑Class SVM, or autoencoders).

---

## 2. Project Structure

```text
secguardian/
├─ main.py                      # Entry point / orchestrator
├─ requirements.txt
├─ Dockerfile
├─ README.md
├─ rules/
│  └─ sample_rules.yar          # Example YARA rules
├─ guardian/
│  ├─ __init__.py
│  ├─ config.py                 # Global configuration dataclass
│  ├─ events.py                 # Event model and EventBus
│  ├─ risk.py                   # Risk scoring engine
│  ├─ crypto_utils.py           # Secure logging (PoC encryption)
│  ├─ adaptive.py               # Baseline/adaptive model
│  ├─ threat_intel.py           # Threat intelligence client (stub)
│  ├─ monitoring/
│  │  ├─ __init__.py
│  │  ├─ process_monitor.py     # Process monitoring
│  │  ├─ network_monitor.py     # Network monitoring
│  │  ├─ filesystem_monitor.py  # File system monitoring
│  │  └─ registry_monitor.py    # Registry autorun monitoring
│  ├─ detection/
│  │  ├─ __init__.py
│  │  ├─ yara_scanner.py        # YARA scanning logic
│  │  ├─ heuristic_engine.py    # Heuristic process scoring
│  │  ├─ ransomware_detector.py # Ransomware indicators
│  │  └─ behavior_analyzer.py   # Behavioral correlation (stub)
│  ├─ forensic/
│  │  ├─ __init__.py
│  │  ├─ collector.py           # Forensic event collector
│  │  └─ timeline.py            # Placeholder for timeline analysis
│  └─ reporting/
│     ├─ __init__.py
│     └─ reporters.py           # JSON/HTML/console reporting
└─ tests/
   ├─ test_risk.py
   ├─ test_heuristic_engine.py
   └─ test_yara_scanner.py
```

---

## 3. Installation

### 3.1 Prerequisites

* **Operating System**: Windows 10 or 11 (recommended)
* **Python**: 3.8 or newer
* **Permissions**:

  * For maximum visibility, run from an account with **Administrator** privileges.
  * However, the security recommendation is to run the tool with **minimum necessary access**.

### 3.2 Clone and Install Dependencies

```bash
# Clone the repository
git clone https://github.com/your-user/secguardian.git
cd secguardian

# Create a virtual environment (recommended)
python -m venv .venv
.venv\Scripts\activate  # روی ویندوز

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt
```

### 3.3 Required Python Packages

`requirements.txt` contains the following:

```text
psutil>=5.9.0
pandas>=1.5.0
scapy>=2.5.0
yara-python>=4.3.0
requests>=2.31.0
watchdog>=4.0.0
```

> Note: Some of these libraries (such as `yara-python` and `scapy`) may require additional build tools or configuration on Windows.

---

## 4. Configuration

The main configuration is done through the `Config` class in `guardian/config.py` and command line arguments.

### 4.1 Command‑line Arguments (main.py)

```bash
python main.py \
  --rules ./rules/sample_rules.yar \
  --log-dir ./logs \
  --debug
```

* `--rules` (required): Path to the file or folder containing the YARA rules.
* `--log-dir`: Path to the logs and reports directory (default: `./logs`).
* `--debug`: Enable debug-level logging.

### 4.2 Config Fields

```python
Config(
    yara_rules_path="./rules/sample_rules.yar",
    log_dir="./logs",
    risk_threshold_high=80.0,
    risk_threshold_medium=40.0,
    adaptive_model_path="./logs/adaptive_baseline.json",
)
```

You can adjust these values ​​based on your laboratory or research needs.

---

## 5. Running SecGuardian

After installing the dependencies:

```bash
python main.py --rules ./rules/sample_rules.yar --log-dir ./logs
```

If you add `--debug`, you will see more detailed logs in the console:

```bash
python main.py --rules ./rules/sample_rules.yar --log-dir ./logs --debug
```

### 5.1 Generated Artifacts

* **Encrypted Forensic Logs**: `logs/forensic.log.enc`

	* Encrypted event logs (PoC‑level encryption).

* **JSON Events**: `logs/events.jsonl`

	* A format suitable for machine learning, SIEM, and Data Science tools.

* **HTML Dashboard**: `logs/dashboard.html`

	* A simple dashboard to view security status and events.

* **Adaptive Baseline**: `logs/adaptive_baseline.json`

	* System baseline information for future comparisons.
---

## 6. YARA Rules

A sample of YARA rules is located in `rules/sample_rules.yar`.
You can:

* Extend this file with your own rules.
* Or pass the path to a directory containing multiple `.yar` files to `--rules`.
### 6.1 Example Rules

```yar
rule Suspicious_Executable_SectionNames
{
    meta:
        description = "Detects binaries with suspicious section names"
        author = "Mobin Yousefi"
        reference = "PoC"

    strings:
        $s1 = ".text"
        $s2 = ".rdata"
        $sus = ".upx"

    condition:
        uint16(0) == 0x5A4D and $sus
}

rule Generic_Encoded_PowerShell
{
    meta:
        description = "PowerShell with encodedcommand"
        author = "Mobin Yousefi"

    strings:
        $ps1 = "powershell"
        $enc = "-encodedcommand"

    condition:
        1 of ($ps*) and $enc
}
```

For research, you can add your own YARA rule sets (e.g. based on specific malware families).
---

## 7. Testing

### 7.1 Unit Tests

This project includes a few sample unit tests in the `tests/` folder:

* `tests/test_risk.py` – Basic test of the risk scoring engine.
* `tests/test_heuristic_engine.py` – Heuristic Engine test for PowerShell.
* `tests/test_yara_scanner.py` – Test of loading YARA rules and behavior in the absence of a target.
### 7.2 Running Tests

1. Install `pytest`:

```bash
pip install pytest
```

2. Run the tests:

```bash
pytest -q
```

You can also cover the behavior of other modules by adding new tests.
---

## 8. Docker Support (Development / CI)

The `Dockerfile` file is designed to run a project in a lightweight Linux container.
This is more suitable for **testing, CI, and code analysis**, not for actual Windows monitoring.

### 8.1 Building the Image

```bash
docker build -t secguardian:latest .
```

### 8.2 Running the Container

```bash
docker run --rm -it secguardian:latest \
  python main.py --rules ./rules/sample_rules.yar --log-dir ./logs
```

> Note: Many Windows-related features (such as `winreg` and Windows registry/process details) are not available in a Linux container and act as PoC or stubs.
---

## 9. Security Considerations & Limitations

### 9.1 What SecGuardian **Can** Do

* Relatively deep user-space monitoring for:

* Processes
	* Network
	* Filesystem
	* Registry (autorun)
* Detect Indicators of Compromise (IoC) such as:
	* Suspicious PowerShell
	* New autoruns
	* Changes to sensitive files
	* Connections to unusual ports
* Use YARA to identify known malware patterns.
* Forensic logging and reporting for further analysis.
### 9.2 What SecGuardian **Cannot** Guarantee

* 100% detection of all types of intrusions:
	* Kernel rootkits
	* Highly advanced fileless malware
	* Specific EDR/AV bypasses

* Complete protection against a professional attacker who has gained control of the system at the kernel level.

### 9.3 Best Practices

* Use this tool as an **investigation/analytical aid** and part of a **multi-layered defense stack**.
* On sensitive machines, be sure to use professional solutions (EDR/AV, SIEM, segmented network, secure hardware, etc.).
* For formal forensics:

	* Use **disk image** and **memory image**.
	* Perform analysis on a separate system.

---

## 10. Roadmap / Future Work

* Add real **Memory Analysis** (e.g. with Volatility or similar tools).
* Full integration with **Threat Intelligence Platforms**.
* Develop **Behavior Correlation Engine** for Kill-Chain modeling.
* Use advanced **Machine Learning** for:

	* Anomaly Detection
	* Advanced Risk Scoring
* Build interactive **GUI/dashboard** (web or desktop) for managing multiple hosts.

---

## 11. License

This project is released under the **MIT License** (if you add a LICENSE file).

You are free to:

* Modify the code.
* Use for educational and research purposes.
* Use parts in your own projects; it will be more professional if you cite the source.
---

## 12. Credits
* Design and Architecture: Inspired by modern EDR/AV concepts, HIDS, and forensics experiences.
* Author: *Mobin Yousefi* – Computer Science & Cybersecurity Research.

If you expand this project (e.g. by adding Memory Forensics or real TI), you can use it as a good **research toolkit** for articles, theses, or industrial PoCs.