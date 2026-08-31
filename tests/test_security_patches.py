"""
tests/test_security_patches.py

Regression unit test suite for Security & Robustness Patches (VULN-01 through VULN-06).
"""

import os
import sys
import json
import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "solo-confi"))

from mcp_servers.webhook_server import post_to_webhook
from engine.entity_linker import extract_entities
from eval.calibration import calibrate_thresholds
from eval.metrics import evaluate_dataset


def test_vuln_01_and_06_scheme_validation_and_url_security():
    """VULN-01 & VULN-06: Verify non-HTTP schemes are rejected by post_to_webhook."""
    # Attempt file scheme SSRF
    result = post_to_webhook(url="file:///etc/passwd", payload="{}")
    result_dict = json.loads(result)

    assert "error" in result_dict
    assert "Invalid URL scheme" in result_dict["error"]


def test_vuln_04_huge_text_payload_redos_protection():
    """VULN-04: Verify entity extraction handles huge 1MB text strings cleanly."""
    huge_text = "secret_key " + ("A" * 1_000_000)
    entities = extract_entities(huge_text)

    assert isinstance(entities, set)
    assert "secret_key" in entities or "secret" in entities


def test_vuln_05_empty_dataset_calibration_safety():
    """VULN-05: Verify calibration engine handles empty benign trace lists gracefully."""
    empty_benign = []
    scorers = {}

    taus = calibrate_thresholds(scorers, empty_benign, target_fpr=0.05)
    assert isinstance(taus, dict)

    empty_metrics = evaluate_dataset(scorers, [], taus)
    assert isinstance(empty_metrics, dict)
    assert empty_metrics["CCG"]["mean_ccg"] == 0.0
