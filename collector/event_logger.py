"""
collector/event_logger.py

The single piece of infrastructure everything else in IntentGuard depends on.
Wraps every observed MCP tool call (server, tool name, arguments, result,
timestamp) into a JSONL trace file, tagged with a trace_id, label, and
category so the same log directory can hold the full IntentBench-Lite
dataset (malicious / benign_plain / benign_similar).

Each trace file is self-describing: a header line, N event lines, and a
footer line. Ground-truth markers (e.g. "this is the step where the attack
objective was achieved") are logged inline so Lead Time can be computed
later without needing a separate label file.
"""

import json
import uuid
from pathlib import Path
from datetime import datetime, timezone
from typing import Any, Dict, Optional


class EventCollector:
    def __init__(
        self,
        log_dir: str = "traces",
        trace_id: Optional[str] = None,
        label: Optional[int] = None,        # 1 = malicious, 0 = benign
        category: Optional[str] = None,     # "malicious" | "benign_plain" | "benign_similar"
        scenario_name: Optional[str] = None,
    ):
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.trace_id = trace_id or str(uuid.uuid4())
        self.label = label
        self.category = category
        self.scenario_name = scenario_name
        self.step_index = 0
        self.trace_path = self.log_dir / f"{self.trace_id}.jsonl"
        self._write_header()

    def _now(self) -> str:
        return datetime.now(timezone.utc).isoformat()

    def _append(self, obj: Dict[str, Any]) -> None:
        with open(self.trace_path, "a") as f:
            f.write(json.dumps(obj, default=str) + "\n")

    def _write_header(self) -> None:
        self._append({
            "type": "trace_header",
            "trace_id": self.trace_id,
            "label": self.label,
            "category": self.category,
            "scenario_name": self.scenario_name,
            "started_at": self._now(),
        })

    def log_event(
        self,
        server: str,
        tool: str,
        arguments: Dict[str, Any],
        result: Any = None,
        error: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Call this once per observed MCP tool invocation, in order."""
        event = {
            "type": "tool_call",
            "trace_id": self.trace_id,
            "step": self.step_index,
            "timestamp": self._now(),
            "server": server,
            "tool": tool,
            "arguments": arguments,
            "result_preview": self._preview(result),
            "error": error,
        }
        self.step_index += 1
        self._append(event)
        return event

    def _preview(self, result: Any, max_chars: int = 800) -> Optional[str]:
        if result is None:
            return None
        try:
            s = result if isinstance(result, str) else json.dumps(result, default=str)
        except Exception:
            s = str(result)
        return s[:max_chars]

    def mark_attack_complete(self, step: Optional[int] = None) -> None:
        """
        Ground-truth annotation: the step index at which the attack objective
        was actually achieved (e.g. the exfiltration POST succeeded). This is
        what Lead Time is measured against — NOT the last step of the trace.
        For benign traces, simply never call this.
        """
        self._append({
            "type": "ground_truth_marker",
            "trace_id": self.trace_id,
            "marker": "attack_complete",
            "step": step if step is not None else self.step_index - 1,
            "timestamp": self._now(),
        })

    def annotate_step(self, step: int, note: str) -> None:
        """Free-text annotation for a specific step (e.g. 'evasion filler read')."""
        self._append({
            "type": "annotation",
            "trace_id": self.trace_id,
            "step": step,
            "note": note,
            "timestamp": self._now(),
        })

    def close(self) -> str:
        self._append({
            "type": "trace_footer",
            "trace_id": self.trace_id,
            "ended_at": self._now(),
            "total_steps": self.step_index,
        })
        return str(self.trace_path)


def load_trace(path: str):
    """Utility: read a trace file back into header / events / footer."""
    header, events, footer, markers, annotations = None, [], None, [], []
    with open(path) as f:
        for line in f:
            obj = json.loads(line)
            t = obj.get("type")
            if t == "trace_header":
                header = obj
            elif t == "trace_footer":
                footer = obj
            elif t == "tool_call":
                events.append(obj)
            elif t == "ground_truth_marker":
                markers.append(obj)
            elif t == "annotation":
                annotations.append(obj)
    return {
        "header": header,
        "events": events,
        "markers": markers,
        "annotations": annotations,
        "footer": footer,
    }
