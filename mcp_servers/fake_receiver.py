"""
mcp_servers/fake_receiver.py

A minimal local HTTP server that stands in for "the outside world" during
trace collection. The webhook MCP server POSTs here. This keeps every
malicious trace fully offline and safe — nothing ever leaves localhost.

Run standalone:
    python3 mcp_servers/fake_receiver.py --port 8765

It logs every received POST body to received_payloads.jsonl in the same
directory it's run from, and returns {"status": "received"}.
"""

import argparse
import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class IngestHandler(BaseHTTPRequestHandler):
    log_path = "received_payloads.jsonl"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        record = {
            "received_at": datetime.now(timezone.utc).isoformat(),
            "path": self.path,
            "body": body,
        }
        with open(self.log_path, "a") as f:
            f.write(json.dumps(record) + "\n")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"status": "received"}).encode("utf-8"))

    def log_message(self, fmt, *args):
        # quiet by default; comment out to see raw HTTP logs
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--log-path", default="received_payloads.jsonl")
    args = parser.parse_args()

    IngestHandler.log_path = args.log_path
    server = ThreadingHTTPServer(("127.0.0.1", args.port), IngestHandler)
    print(f"Fake exfiltration receiver listening on http://127.0.0.1:{args.port}")
    print(f"Logging received payloads to {args.log_path}")
    server.serve_forever()


if __name__ == "__main__":
    main()
