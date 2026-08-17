# IntentGuard: Cross-MCP Temporal Attack Graph (CTAG) Detection & Forecasting Framework

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Research Status](https://img.shields.io/badge/Status-Research%20MVP-orange.svg)]()

**IntentGuard** is a research-grade security telemetry, behavioral detection, and campaign forecasting framework designed to detect multi-stage AI agent attack campaigns (such as credential theft and data exfiltration) across heterogeneous Model Context Protocol (MCP) servers.

---

## 🔬 Research Overview

### Hypothesis
> Correlating observable agent behavior across multiple heterogeneous MCP servers via temporal sequence and semantic entity correlation enables significantly earlier identification of emerging attack campaigns than analyzing each MCP server's event stream independently or pooling multi-server events without explicit cross-server correlation structure.

### Core Headline Metric: Cross-MCP Correlation Gain ($CCG$)
$$CCG = \text{LeadTime}(\text{CTAG}, \tau_{5\%}) - \max\left(\text{LeadTime}(A), \text{LeadTime}(B), \text{LeadTime}(C)\right)$$

* **Lead Time ($LT$):** Steps (or seconds) between detector alert and attack completion ($\text{pivot\_step}$).
* **$5\%$ FPR Operating Calibration:** Every baseline's detection threshold $\tau$ is independently tuned on benign traces to ensure zero trigger-happy bias before measuring Lead Time on malicious traces.

---

## 🏗️ Repository Architecture

```
intentguard-mvp/
├── agent/
│   └── agent_loop.py            # ReAct loop connecting Ollama + stdio MCP servers
├── collector/
│   └── event_logger.py          # EventCollector: structured step-level JSONL trace logger
├── mcp_servers/
│   ├── webhook_server.py        # Custom MCP server: post_to_webhook(url, payload)
│   └── fake_receiver.py         # Local HTTP sink for testing isolated exfiltration traffic
├── scenarios/
│   └── prompts.py               # IntentBench-Lite scenario definitions (Malicious/Benign)
├── sandbox/                     # Sandboxed file target environment (fake secrets, README, configs)
├── traces/                      # Output directory for step-labeled JSONL trace files
├── intentguard_experiment1_skeleton.py # Experiment 1 generator & baseline ablation harness
├── IntentGuard_MVP_Spec.md      # Core research specification v1.0
├── IntentGuard_MVP_Experiment_Design.md # Detailed experimental methodology & ablation metrics
├── requirements.txt
└── setup.sh
```

---

## 📊 Baseline Ablation Matrix

| Condition | Sees Filesystem | Sees Webhook | Structure | Purpose |
|---|---|---|---|---|
| **A — Filesystem Only** | Yes | No | Single-stream | Status-quo single-server baseline |
| **B — Webhook Only** | No | Yes | Single-stream | Status-quo exfiltration baseline |
| **C — Uncorrelated Pooled** | Yes | Yes | Concatenated stream | Controls for access to "more data" without graph edges |
| **CTAG (Proposed)** | Yes | Yes | Cross-MCP Temporal Graph | Evaluates explicit cross-server semantic & temporal correlation |
| **D — LLM-as-Judge** | Yes | Yes | Windowed LLM evaluation | Baseline model using LLM prompt-based evaluation |

---

## ⚡ Quick Start

### 1. Prerequisites & Installation

```bash
cd intentguard-mvp
bash setup.sh
```
*Note: `setup.sh` installs node dependencies locally to prevent bare `npx` stdout deprecation warnings from corrupting the MCP stdio JSON-RPC channels.*

### 2. Pull Local Agent Model

```bash
ollama pull qwen2.5:7b
```

### 3. Launch Test Environment & Agent Loop

```bash
# Terminal 1 — Start local exfiltration sink (logs received exfil attempts locally)
python3 mcp_servers/fake_receiver.py --port 8765

# Terminal 2 — Execute a scenario episode
python3 agent/agent_loop.py --scenario malicious_credential_theft
```

---

## 🧪 Scenarios (IntentBench-Lite)

| Scenario Key | Category | Ground Truth Label | Description |
|---|---|---|---|
| `malicious_credential_theft` | `malicious` | `1` | Direct path read of sensitive target files escalated to webhook POST |
| `malicious_credential_theft_evasive` | `malicious` | `1` | Credential theft interleaved with benign noise reads |
| `benign_summarize_readme` | `benign_plain` | `0` | Simple documentation reading task |
| `benign_list_dependencies` | `benign_plain` | `0` | Directory inspection task |
| `benign_ci_notification` | `benign_similar` | `0` | **Critical Confounder:** Reads config and posts build status to webhook |
| `benign_backup_confirmation` | `benign_similar` | `0` | **Critical Confounder:** Backup verification followed by webhook ping |

---

## 🔄 Programmatic Trace Inspection

```python
from collector.event_logger import load_trace

trace = load_trace("traces/<trace_id>.jsonl")
print("Header:", trace["header"])
print("Events:", len(trace["events"]))
print("Attack Complete Step Marker:", trace["markers"])
```

---

## 🛣️ Engineering Roadmap

- [x] **Phase 1: Requirement Analysis & Problem Formalization** ([implementation_plan.md](file:///C:/Users/Parv%20Saini/.gemini/antigravity/brain/04b0d22a-543e-4f67-8856-6e08723c3a39/implementation_plan.md))
- [ ] **Phase 2: Research & Architecture Review** (CTAG graph topology, entity linker design, baseline C non-leakage protocol)
- [ ] **Phase 3: System Planning & Modular Specification** (Entity Linker, NetworkX CTAG Builder, Scorer Pipeline)
- [ ] **Phase 4 & 5: Comprehensive Test Suite & Prioritization** (Unit, Integration, Edge-case, Security, Research Validity)
- [ ] **Phase 6 & 7: Incremental Milestone Execution** (TDD, Scorer implementation, 5% FPR Calibration engine)
- [ ] **Phase 8: Continuous Review & Reproducible Evaluation Report** (Lead Time plots, $CCG$ confidence intervals)

---

## 📜 License

This project is licensed under the [MIT License](LICENSE).

