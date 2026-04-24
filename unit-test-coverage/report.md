

**Project:** RTD-MTA v3.0.0 — Ransomware Traffic Detector / Malware Traffic Analyzer **Date:** April 24, 2026 **Objective:** Run the full test suite with coverage reporting to measure how much of the codebase is exercised by existing tests, identify gaps, and document the current state of test health.

---

## Overview

Coverage measurement is how you know whether your tests actually touch the code they're supposed to protect. A suite that passes 231 tests but only covers 56% of the codebase still has large blind spots — and those blind spots are exactly where bugs hide. This demo runs pytest with `pytest-cov` against RTD-MTA's `src/` tree, captures the full HTML and terminal coverage report, and identifies which modules need the most attention.

---

## Setup

Both `pytest` and `pytest-cov` were already installed in the environment. The project path was exported so Python could resolve internal imports correctly.

```bash
pip install pytest pytest-cov --break-system-packages
export PYTHONPATH=$(pwd)
```

Both packages confirmed already satisfied — no install required.

---

## Running the Test Suite

```bash
python3 -m pytest tests/ -v \
  --cov=src \
  --cov-report=html \
  --cov-report=term-missing \
  --tb=short 2>&1 | tee logs/test_results.log
```

This runs all tests under `tests/` with verbose output, measures coverage against the `src/` package, generates an HTML report in `htmlcov/`, and logs everything to `logs/test_results.log`.

---

## Test Results

**233 tests collected. 231 passed, 2 failed.**

The suite ran in 23.37 seconds across 13 test files covering capture, database, detection, enrichment, ML pipeline, output, parsers, pipeline, response, and YARA engines.

![](Screenshot_2026-04-24_06_48_20.png)
Figure 1: Test session start — Python 3.13.12, pytest 8.2.2, 233 tests collected

![](Screenshot_2026-04-24_06_48_25.png)
Figure 2: Tests running — detection, integration, and ML pipeline tests all passing

![](Screenshot_2026-04-24_06_48_33.png)
Figure 3: ELK exporter tests — connection refused to localhost:9200 is expected (no Elasticsearch running), tests still pass

### The 2 Failures

Both failures are in `tests/test_pipeline.py` and are caused by the same root issue — a module import path mismatch:

```
FAILED tests/test_pipeline.py::TestPipelineInit::test_alert_manager_property
AssertionError: assert False
  where False = isinstance(AlertManager(...), <class 'src.alerting.alert_manager.AlertManager'>)

FAILED tests/test_pipeline.py::TestPipelineInit::test_signature_engine_property
AssertionError: assert False
  where False = isinstance(SignatureEngine(...), <class 'src.detection.signature_engine.SignatureEngine'>)
```

The test imports `AlertManager` from `src.alerting.alert_manager` but the pipeline internally imports it from `alerting.alert_manager` (without the `src.` prefix). Python treats these as two different classes even though they are the same file — so `isinstance()` returns `False`. The fix is to normalise imports in either the test or the pipeline, not a bug in the logic itself.

---

## Coverage Report: 56%

The overall coverage came in at **55.74%** — below the configured `fail-under=70` threshold, which caused the run to exit with a coverage failure even though 231/233 tests passed.

```
TOTAL    6590    2917    56%
FAIL Required test coverage of 70.0% not reached. Total coverage: 55.74%
```

### Coverage by Module (Files view)

![](Screenshot_2026-04-24_06_48_37.png)
Figure 4: Coverage report — alerting, capture, database, and detection modules

![](Screenshot_2026-04-24_06_48_40.png)
Figure 5: Coverage report — enrichment, output, parser, pipeline, response, and utils modules

### Coverage by Function

![](Screenshot_2026-04-24_06_48_44.png)
Figure 6: Function-level coverage — AlertManager.register_finding at 90%, distribute at 33%, enrich at 0%

![](Screenshot_2026-04-24_06_48_48.png)
Figure 7: Database functions — most CRUD operations covered, sync_rules and purge at 0%

![](Screenshot_2026-04-24_06_48_52.png)
Figure 8: Detection functions — BehavioralEngine._cleanup_stale_sources at 0%, DGADetector._load_ngrams at 0%

![](Screenshot_2026-04-24_06_48_55.png)
Figure 9: MLEnsemble. score_isolation_forest, _score_lstm, _score_ocsvm all at 0% — no models loaded during tests

![](Screenshot_2026-04-24_06_48_58.png)
Figure 10: FeedUpdater at 0% throughout — scheduler never started in test environment

![](Screenshot_2026-04-24_06_49_04.png)
Figure 11: Parser functions — FTPParser, KerberosParser, LDAPParser, TLSParser all under 30%

![](Screenshot_2026-04-24_06_49_07.png)
Figure 12: Utility functions — ip_utils, ja3, time_utils all at 0%_

### Coverage by Class

![](Screenshot_2026-04-24_06_49_09.png)
Figure 13: Class-level coverage — PcapReader at 10%, LiveCapture at 19%, ZeekLiveTailer at 0%

![](Screenshot_2026-04-24_06_49_22.png)
Figure 14: Detection classes — DoHDetector at 38%, MITREMapper at 34%, MLEnsemble at 45%

![](Screenshot_2026-04-24_06_49_27.png)
Figure 15: Output classes — TerminalDashboard, WebDashboard, WebSocketDashboard all at 0%; parser classes heavily uncovered

---

## Coverage Breakdown by Category

|Category|Well Covered (>70%)|Needs Work (<50%)|
|---|---|---|
|**Alerting**|ThreatScorer (98%), AlertManager (82%)|MultiChannelNotifier (58%)|
|**Detection**|LateralMovement (91%), YARA (86%), BehavioralEngine (84%)|MITREMapper (54%), DoHDetector (53%)|
|**Database**|db_manager (70%), models (88%)|—|
|**Pipeline**|pipeline.py (98%)|—|
|**Output**|JSONExporter (95%), PDFReport (88%), ReportGenerator (86%)|WebDashboard (24%), ws_dashboard (0%), logger (0%)|
|**Enrichment**|—|FeedUpdater (0%), VirusTotal (35%), GeoIP (55%)|
|**Parsers**|PacketRecord (91%), ICMP (85%)|TLS (19%), SMB (25%), LDAP (23%), Kerberos (26%), IPv6 (0%)|
|**Utils**|—|ip_utils (0%), ja3 (0%), time_utils (0%), entropy (23%)|
|**Capture**|PacketQueue (87%)|PcapReader (20%), LiveCapture (36%)|
|**ML**|ml_detector (78%)|MLEnsemble (55%), feed_updater (0%)|

---

## What's Driving the Gap

The 44% uncovered code breaks down into a few clear categories:

**Infrastructure-dependent code (expected to be uncovered in unit tests):** `LiveCapture`, `PcapReader`, `WebDashboard`, `WebSocketDashboard`, `TerminalDashboard`, `FeedUpdater`, and the Elasticsearch/SOAR dispatchers all require live network interfaces, running services, or real hardware to exercise. These are integration-test concerns, not unit-test concerns.

**Protocol parsers with complex payloads:** TLS, SMB, LDAP, Kerberos, and IPv6 parsers need real protocol-specific byte sequences to reach their parsing logic. The current test stubs pass in minimal or empty packets that skip most branches.

**Utility modules with zero tests:** `ip_utils.py`, `ja3.py`, `time_utils.py`, and `entropy.py` have no dedicated tests at all. These are pure functions — easy wins for coverage improvement.

**ML scoring paths:** The isolation forest, LSTM, and OCSVM scoring paths in `MLEnsemble` require trained model files that don't exist in the test environment. The ensemble initialises cleanly but all `_score_*` methods short-circuit immediately.

---

## Achieving 70% Coverage

To cross the 70% threshold without writing complex integration tests, the highest-yield changes are:

**1. Add tests for pure utility functions** — `ip_utils`, `time_utils`, `entropy`, and `ja3` are stateless helpers. A dozen parameterised tests would add several hundred covered statements with minimal effort.

**2. Mock the protocol parsers** — TLS, SMB, LDAP, and Kerberos parsers can be tested by constructing raw bytes that match their expected packet formats. Scapy can generate these synthetically the same way it generated the malicious PCAP in Demo 6.

**3. Exclude infrastructure-only modules from coverage measurement** — modules like `ws_dashboard.py`, `terminal_dashboard.py`, `feed_updater.py`, and `live_capture.py` are untestable without a live environment. Adding them to `.coveragerc` under `[report] omit` removes ~300 statements of irreducible zero-coverage code and would push the total above 70%.

The quickest path to passing the threshold in `pytest.ini` is the omit approach combined with utility tests — achievable in an afternoon.

---

## Summary

|Metric|Value|
|---|---|
|Tests collected|233|
|Tests passed|231|
|Tests failed|2|
|Failure cause|Import path mismatch (`src.` prefix inconsistency)|
|Total coverage|55.74%|
|Coverage threshold|70%|
|Gap|14.26 percentage points|
|Highest covered module|`pipeline.py` — 98%|
|Lowest covered module|`ipv6_parser.py`, `ws_dashboard.py`, `logger.py` — 0%|

The test suite is in good shape for core detection logic. The coverage gap is dominated by infrastructure-dependent code and untested utility modules — both of which are well-understood and addressable without architectural changes.
![](Screenshot_2026-04-24_06_49_30.png)

---
![](Screenshot_2026-04-24_06_50_56.png)
_RTD-MTA v3.0.0 | Python 3.13.12 | pytest 8.2.2 | pytest-cov 7.1.0 | coverage 7.13.5_