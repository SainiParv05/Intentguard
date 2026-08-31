"""
engine/feature_extractor.py

Topological & Semantic Graph Feature Extractor for IntentGuard CTAG.
Converts a NetworkX DiGraph or MultiDiGraph representation into a 10-dimensional numerical feature vector
for model classification and ablation evaluation.
"""

import networkx as nx
import numpy as np
from typing import Any


def extract_graph_features(G: Any) -> np.ndarray:
    """
    Extracts a 10-dimensional numerical feature vector from a CTAG graph:
    [num_nodes, num_edges, num_entity_edges, max_suspicion, mean_suspicion,
     max_entity_weight, has_entity_edge, pagerank_max, max_degree, total_weight]
    """
    if G.number_of_nodes() == 0:
        return np.zeros(10, dtype=np.float32)

    num_nodes = float(G.number_of_nodes())
    num_edges = float(G.number_of_edges())

    all_edges_data = [d for u, v, d in G.edges(data=True)]
    entity_edges = [d for d in all_edges_data if d.get("edge_type") == "entity_overlap"]
    num_entity_edges = float(len(entity_edges))

    sus_scores = [d.get("suspicion", 0.0) for _, d in G.nodes(data=True)]
    max_suspicion = float(max(sus_scores)) if sus_scores else 0.0
    mean_suspicion = float(np.mean(sus_scores)) if sus_scores else 0.0

    entity_weights = [d.get("weight", 0.0) for d in entity_edges]
    max_entity_weight = float(max(entity_weights)) if entity_weights else 0.0
    has_entity_edge = 1.0 if num_entity_edges > 0 else 0.0

    total_weight = float(sum(d.get("weight", 0.0) for d in all_edges_data))
    max_degree = float(max([d for n, d in G.degree()])) if num_nodes > 0 else 0.0

    try:
        simple_G = nx.DiGraph(G)
        pr = nx.pagerank(simple_G)
        pagerank_max = float(max(pr.values())) if pr else 0.0
    except Exception:
        pagerank_max = 0.0

    features = [
        num_nodes,
        num_edges,
        num_entity_edges,
        max_suspicion,
        mean_suspicion,
        max_entity_weight,
        has_entity_edge,
        pagerank_max,
        max_degree,
        total_weight,
    ]

    return np.array(features, dtype=np.float32)
