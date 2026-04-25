# RTD-MTA  Finding Reports

**Project:** Ransomware Traffic Detector / Malware Traffic Analyzer v3.0.0  
**Author:** Manjil Katuwal (Hiro001)  
**Repo:** [hiro001-eth/Ransomware-Traffic-Detector-Integrated-with-Malware-Traffic-Analyzer](https://github.com/hiro001-eth/Ransomware-Traffic-Detector-Integrated-with-Malware-Traffic-Analyzer)

---

This folder contains hands-on demonstration reports for RTD-MTA. Each report documents a real test run  with actual terminal output, screenshots, and analysis  showing the system working against live traffic, synthetic attack simulations, and real malware PCAPs.

These are not theoretical write-ups. Every result shown was produced by running the tool.

---

## Reports

### 1. Multi-Engine Threat Analysis (The Money Shot)
> The core detection demo. RTD-MTA is run against a real malicious PCAP. Multiple detection engines fire simultaneously  signature matching, behavioral analysis, DGA detection, and C2 beaconing  producing a full incident report with MITRE ATT&CK mappings.

📄 [Read Report](multi-engine-threat-analysis/report.md)

---

### 2. SOC Analyst TUI (Terminal User Interface)
> The live dashboard demo. Shows the Rich terminal UI running in real time  the 4-panel layout with live alert feed, top talkers, protocol distribution, and PPS sparkline. Demonstrates what a Tier 1 SOC analyst sees during an active monitoring session.

📄 [Read Report](soc-analyst-tui/report.md)

---

### 3. Applied ML & AI  Isolation Forest Training
> The ML pipeline demo. Trains the Isolation Forest baseline model on normal traffic, then validates it detects anomalies. Shows feature extraction, model serialisation, and threshold calibration  the full training-to-detection cycle.

📄 [Read Report](ml-isolation-forest-training/report.md)

---

### 4. False Positive Tuning
> The analyst workflow demo. Runs RTD-MTA against a known-clean Wireshark sample PCAP, measures the baseline false positive count, tunes the deduplication window and behavioral thresholds in config/settings.yaml, and re-runs to show a 50% FP reduction  without breaking real threat detection.

📄 [Read Report](false-positive-tuning/report.md)

---

### 5. Unit Test Coverage Report
> The code quality demo. Runs the full 233-test pytest suite with pytest-cov coverage measurement across src/. Documents 231 passing tests, 2 failures (import path mismatch  not logic bugs), and 56% total coverage with a module-by-module breakdown of what is covered and what needs work.

📄 [Read Report](unit-test-coverage/report.md)

---

### 6. Performance Benchmark
> The throughput demo. A synthetic load of 10,000 HTTP packets is pushed through the packet parser to measure real throughput and latency. Results: 1,229 packets/second, median latency 0.597ms, p99 2.745ms. Includes analysis of what drives the numbers and what to expect in a full live pipeline.

📄 [Read Report](performance-benchmark/report.md)

---

## Quick Reference

| Report | What It Shows | Key Result |
|---|---|---|
| Multi-Engine Threat Analysis | Core detection works | Multiple engines fire on real malware |
| SOC Analyst TUI | Usable in a real SOC | Live 4-panel dashboard, real-time alerts |
| Isolation Forest Training | ML pipeline end-to-end | Model trains, serialises, detects anomalies |
| False Positive Tuning | Analyst can tune the system | 50% FP reduction without breaking detection |
| Unit Test Coverage | Codebase is tested | 231/233 tests pass, 56% coverage mapped |
| Performance Benchmark | System is fast enough | 1,229 pps, 0.597ms median latency |

---

*RTD-MTA v3.0.0  Built by Manjil Katuwal (Hiro001)*
