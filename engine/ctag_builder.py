"""
engine/ctag_builder.py

NetworkX MultiDiGraph Builder for IntentGuard CTAG.
Converts raw trace streams into Cross-MCP Temporal Attack Graphs:
- Nodes: Individual tool invocation steps with attribute features.
- Edges: Strict temporal sequence edges (control flow) and cross-MCP transitive entity overlap edges (data flow).
"""

import networkx as nx
from typing import Dict, Any, List, Optional
from engine.entity_linker import extract_entities, compute_entity_overlap

SERVER_MAP = {"filesystem": 0, "database": 1, "shell_exec": 2, "webhook": 3}


def build_ctag(trace_dict: Dict[str, Any], max_step: Optional[int] = None) -> nx.MultiDiGraph:
    """
    Constructs a NetworkX MultiDiGraph representing the Cross-MCP Temporal Attack Graph.

    Parameters:
        trace_dict: Dictionary representation of a Trace (from load_trace or dataset).
        max_step: Optional step index cutoff for online step-by-step graph construction.

    Returns:
        nx.MultiDiGraph where nodes represent tool invocations and edges represent temporal
        sequence and cross-MCP entity flow.
    """
    G = nx.MultiDiGraph()
    events = trace_dict.get("events", [])
    if max_step is not None:
        events = events[: max_step + 1]

    for step_idx, ev in enumerate(events):
        server = ev.get("server", "unknown")
        tool = ev.get("tool", "unknown")
        args = ev.get("arguments", {})
        res = ev.get("result_preview", "")

        args_entities = extract_entities(args)
        has_sensitive_kw = any(kw in args_entities for kw in {"env", "secret", "id_rsa", "credential", "password", "aws_access_key"})
        suspicion = 0.8 if has_sensitive_kw else 0.1

        G.add_node(
            step_idx,
            server=server,
            tool=tool,
            server_id=SERVER_MAP.get(server, 0),
            suspicion=suspicion,
            timestamp=ev.get("timestamp", ""),
            result_preview=res,
            args=args,
        )

        # 1. Strict Temporal Control Flow Edge
        if step_idx > 0:
            G.add_edge(step_idx - 1, step_idx, key="temporal", edge_type="temporal", weight=0.2)

        # 2. Cross-MCP Transitive Data Flow Edges
        for prev_idx in range(step_idx):
            prev_node = G.nodes[prev_idx]
            prev_server = prev_node["server"]
            prev_res = prev_node["result_preview"]

            if prev_server != server:
                weight = compute_entity_overlap(prev_res, args)
                if weight > 0.0:
                    G.add_edge(prev_idx, step_idx, key="entity_overlap", edge_type="entity_overlap", weight=weight)

    return G
