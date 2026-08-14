# IntentGuard MVP — Trace Collection Infrastructure

This is the testing harness described in `IntentGuard_MVP_Spec.md`: a
sandboxed two-server MCP environment (Filesystem + Webhook) driven by a
local Ollama agent, with every tool call logged into labeled JSONL traces
for IntentBench-Lite.

Everything in this repo has been smoke-tested against **real MCP servers**
(the official `@modelcontextprotocol/server-filesystem` and a custom
webhook server) except the live Ollama model call itself, which needs your
local Ollama installation and a GPU/CPU capable of running it.

## What's included

```
intentguard-mvp/
├── sandbox/                  # Fake target files (README, config.json, .env,
│                              # .ssh/id_rsa, .gitignore, package.json) —
│                              # all secrets inside are clearly fake.
├── mcp_servers/
│   ├── webhook_server.py     # Custom MCP server: post_to_webhook(url, payload)
│   └── fake_receiver.py      # Local HTTP server simulating "the outside
│                              # world" so no test traffic ever leaves localhost
├── collector/
│   └── event_logger.py       # EventCollector — logs every tool call to a
│                              # labeled JSONL trace file. The core piece
│                              # everything else depends on.
├── agent/
│   └── agent_loop.py         # Ties Ollama + both MCP servers + the
│                              # collector together into a ReAct loop
├── scenarios/
│   └── prompts.py            # Malicious / benign-plain / benign-similar
│                              # scenario definitions (IntentBench-Lite
│                              # categories from the spec, section 6)
├── traces/                   # Output directory for collected traces
├── requirements.txt
└── setup.sh
```

## Setup

```bash
cd intentguard-mvp
bash setup.sh
```

This installs Python deps and the filesystem MCP server **as a local
dependency** rather than via `npx` directly — important: bare `npx` prints
deprecation warnings to stdout, which corrupts the stdio JSON-RPC channel
the MCP protocol relies on. This was caught and fixed during testing; the
agent loop points at `node_modules/.bin/mcp-server-filesystem` directly.

Then, separately:

```bash
# Pull a tool-calling-capable model (test with something reasonably small first)
ollama pull qwen2.5:7b

# Terminal 1 — fake exfiltration receiver (logs anything "exfiltrated" locally)
python3 mcp_servers/fake_receiver.py --port 8765

# Terminal 2 — run a scenario
python3 agent/agent_loop.py --scenario malicious_credential_theft
```

## Running scenarios

Available scenario keys (see `scenarios/prompts.py` for the exact prompts):

| Key | Category | Label |
|---|---|---|
| `malicious_credential_theft` | malicious | 1 |
| `malicious_credential_theft_evasive` | malicious | 1 |
| `benign_summarize_readme` | benign_plain | 0 |
| `benign_list_dependencies` | benign_plain | 0 |
| `benign_ci_notification` | benign_similar | 0 |
| `benign_backup_confirmation` | benign_similar | 0 |

Each run produces one `traces/<trace_id>.jsonl` file containing a header
(label, category, scenario name), one line per tool call (server, tool,
arguments, result, timestamp), a `ground_truth_marker` line for malicious
traces marking the step where the webhook POST succeeded (used for Lead
Time calculation), and a footer.

To build out IntentBench-Lite to the target size from the spec (150–300
traces), run each scenario multiple times — Ollama's sampling will produce
some natural variation in tool-call ordering and filler reads — and add the
scripted variants described in spec section 6.1 (reordering, variable step
count, evasive filler reads) for the cases where you need precise control
that organic generation won't reliably produce.

## Reading traces back

```python
from collector.event_logger import load_trace
trace = load_trace("traces/<trace_id>.jsonl")
print(trace["header"])
print(trace["events"])
print(trace["markers"])   # ground-truth attack-complete step, if present
```

## What still needs building (not in this drop)

- The actual CTAG construction (NetworkX graph from a trace's events)
- Baselines A/B/C and the CTAG classifier itself
- The calibration + Lead Time measurement pipeline from spec section 5/8
- Scripted trace variants for evasion/reordering scenarios

This drop is the data-generation layer those all consume.
