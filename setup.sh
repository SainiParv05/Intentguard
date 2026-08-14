#!/usr/bin/env bash
# One-time setup. Run from the intentguard-mvp/ directory.
set -e

echo "Installing Python dependencies..."
pip install -r requirements.txt --break-system-packages

echo "Installing the official Filesystem MCP server locally (avoids npx's noisy"
echo "stdout warnings, which break the stdio JSON-RPC channel)..."
npm install @modelcontextprotocol/server-filesystem --silent

echo ""
echo "Setup complete. Next steps:"
echo "  1. Make sure Ollama is running locally: ollama serve"
echo "  2. Pull a tool-calling-capable model:    ollama pull qwen2.5:7b"
echo "  3. In one terminal, start the fake exfiltration receiver:"
echo "       python3 mcp_servers/fake_receiver.py --port 8765"
echo "  4. In another terminal, run a scenario:"
echo "       python3 agent/agent_loop.py --scenario malicious_credential_theft"
echo "       python3 agent/agent_loop.py --scenario benign_ci_notification"
echo "  5. Inspect the resulting trace files in traces/"
