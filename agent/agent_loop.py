"""
agent/agent_loop.py

Runs a ReAct-style agent loop: Ollama decides which tool to call next,
the call gets dispatched to whichever MCP server (Filesystem or Webhook)
owns that tool, the result is logged via EventCollector, and the loop
continues until the model stops calling tools or a step limit is hit.

Requires:
  - Ollama running locally with a tool-calling-capable model pulled, e.g.:
        ollama pull qwen2.5:7b
  - The local filesystem MCP server installed (see setup.sh / README.md)
  - mcp_servers/webhook_server.py runnable via `python3`
  - The fake receiver running separately if testing exfiltration scenarios:
        python3 mcp_servers/fake_receiver.py --port 8765

Usage:
    python3 agent/agent_loop.py --scenario malicious_credential_theft
    python3 agent/agent_loop.py --scenario benign_ci_notification
"""

import argparse
import asyncio
import json
import os
import sys
from contextlib import AsyncExitStack
from typing import Any, Dict, List

import ollama
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from collector.event_logger import EventCollector
from scenarios.prompts import SCENARIOS

MODEL_NAME = os.environ.get("INTENTGUARD_MODEL", "qwen2.5:7b")
MAX_STEPS = 12


class MultiServerAgent:
    """
    Owns connections to multiple MCP servers, presents their combined tool
    list to Ollama, and routes each tool call to the correct server.
    """

    def __init__(self, sandbox_dir: str, fs_binary: str, webhook_script: str):
        self.sandbox_dir = sandbox_dir
        self.fs_binary = fs_binary
        self.webhook_script = webhook_script
        self.exit_stack = AsyncExitStack()
        self.sessions: Dict[str, ClientSession] = {}     # server label -> session
        self.tool_to_server: Dict[str, str] = {}         # tool name -> server label
        self.ollama_tools: List[Dict[str, Any]] = []

    async def connect(self):
        # --- Filesystem MCP server ---
        fs_params = StdioServerParameters(command=self.fs_binary, args=[self.sandbox_dir])
        fs_read, fs_write = await self.exit_stack.enter_async_context(stdio_client(fs_params))
        fs_session = await self.exit_stack.enter_async_context(ClientSession(fs_read, fs_write))
        await fs_session.initialize()
        self.sessions["filesystem"] = fs_session

        # --- Webhook MCP server ---
        wh_params = StdioServerParameters(command="python3", args=[self.webhook_script])
        wh_read, wh_write = await self.exit_stack.enter_async_context(stdio_client(wh_params))
        wh_session = await self.exit_stack.enter_async_context(ClientSession(wh_read, wh_write))
        await wh_session.initialize()
        self.sessions["webhook"] = wh_session

        # Build the combined tool list in Ollama's function-calling format
        for label, session in self.sessions.items():
            listing = await session.list_tools()
            for t in listing.tools:
                self.tool_to_server[t.name] = label
                self.ollama_tools.append({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description or "",
                        "parameters": t.inputSchema,
                    },
                })

    async def call_tool(self, name: str, arguments: Dict[str, Any]):
        server_label = self.tool_to_server.get(name)
        if server_label is None:
            return server_label, None, f"Unknown tool: {name}"
        session = self.sessions[server_label]
        try:
            result = await session.call_tool(name, arguments)
            text_parts = [b.text for b in result.content if hasattr(b, "text")]
            return server_label, "\n".join(text_parts), None
        except Exception as e:
            return server_label, None, str(e)

    async def close(self):
        await self.exit_stack.aclose()


async def run_episode(scenario_key: str, log_dir: str = "traces", max_steps: int = MAX_STEPS):
    scenario = SCENARIOS[scenario_key]
    sandbox_dir = os.path.abspath("sandbox")
    fs_binary = os.path.abspath("node_modules/.bin/mcp-server-filesystem")
    webhook_script = os.path.abspath("mcp_servers/webhook_server.py")

    agent = MultiServerAgent(sandbox_dir, fs_binary, webhook_script)
    await agent.connect()

    collector = EventCollector(
        log_dir=log_dir,
        label=scenario["label"],
        category=scenario["category"],
        scenario_name=scenario_key,
    )

    messages = [
        {"role": "system", "content": scenario["system_prompt"]},
        {"role": "user", "content": scenario["user_prompt"]},
    ]

    print(f"\n=== Running scenario: {scenario_key} (label={scenario['label']}) ===")

    try:
        for step in range(max_steps):
            response = ollama.chat(
                model=MODEL_NAME,
                messages=messages,
                tools=agent.ollama_tools,
            )
            msg = response["message"]
            messages.append(msg)

            tool_calls = msg.get("tool_calls") or []
            if not tool_calls:
                print(f"[step {step}] Agent stopped calling tools. Final message:")
                print(msg.get("content", ""))
                break

            for call in tool_calls:
                fn_name = call["function"]["name"]
                fn_args = call["function"]["arguments"]
                if isinstance(fn_args, str):
                    try:
                        fn_args = json.loads(fn_args)
                    except json.JSONDecodeError:
                        fn_args = {}

                server_label, result_text, error = await agent.call_tool(fn_name, fn_args)
                print(f"[step {step}] {server_label}.{fn_name}({fn_args}) -> "
                      f"{'ERROR: ' + error if error else (result_text or '')[:120]}")

                collector.log_event(
                    server=server_label or "unknown",
                    tool=fn_name,
                    arguments=fn_args,
                    result=result_text,
                    error=error,
                )

                # Heuristic ground-truth marker for the demo scenarios:
                # mark attack_complete the moment a webhook POST happens
                # in a malicious-labeled trace. Real dataset construction
                # should do this more carefully per-scenario.
                if scenario["label"] == 1 and fn_name == "post_to_webhook" and error is None:
                    collector.mark_attack_complete()

                messages.append({
                    "role": "tool",
                    "content": result_text if error is None else f"ERROR: {error}",
                })
        else:
            print(f"[max_steps={max_steps} reached without the agent stopping naturally]")
    finally:
        trace_path = collector.close()
        await agent.close()
        print(f"Trace written to {trace_path}")

    return trace_path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", required=True, choices=list(SCENARIOS.keys()))
    parser.add_argument("--log-dir", default="traces")
    parser.add_argument("--max-steps", type=int, default=MAX_STEPS)
    args = parser.parse_args()
    asyncio.run(run_episode(args.scenario, args.log_dir, args.max_steps))


if __name__ == "__main__":
    main()
