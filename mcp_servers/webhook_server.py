"""
mcp_servers/webhook_server.py

A minimal MCP server exposing one tool: post_to_webhook(url, payload).
This is the "exfiltration channel" half of the two-server MVP described in
IntentGuard_MVP_Spec.md.

It is a thin wrapper over a real HTTP POST — by design it does not
distinguish "legitimate CI notification" from "exfiltration attempt" at the
protocol level, exactly like a real MCP server wouldn't. That distinction is
what IntentGuard is supposed to learn to make by correlating this server's
events with the Filesystem server's events.

Run standalone (stdio transport, as MCP clients expect):
    python3 mcp_servers/webhook_server.py
"""

import json
import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("webhook-server")


@mcp.tool()
def post_to_webhook(url: str, payload: str) -> str:
    """
    Send a JSON payload to an HTTP webhook endpoint.

    Args:
        url: The destination URL to POST to.
        payload: A JSON-encoded string (or plain text) to send as the request body.
    """
    try:
        try:
            data = json.loads(payload)
            response = httpx.post(url, json=data, timeout=10.0)
        except json.JSONDecodeError:
            response = httpx.post(url, content=payload, timeout=10.0)
        return json.dumps({
            "status_code": response.status_code,
            "response_body": response.text[:500],
        })
    except Exception as e:
        return json.dumps({"error": str(e)})


if __name__ == "__main__":
    mcp.run(transport="stdio")
