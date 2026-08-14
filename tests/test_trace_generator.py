"""
tests/test_trace_generator.py

Unit test suite for Segment 1 trace generator and schema validator.
"""

import json
import os
import shutil
import sys
import tempfile
import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from generator.schema_validator import validate_trace
from generator.trace_generator import (
    SCENARIO_GENERATORS,
    generate_dataset,
    save_dataset_to_dir,
)


def test_scenario_generator_counts():
    """Verify dataset generation produces expected scenario proportions."""
    dataset = generate_dataset(n_per_scenario=5, seed=123)
    assert len(dataset) == 7 * 5  # 7 scenarios * 5 traces each = 35

    scenarios_found = {t.scenario for t in dataset}
    assert len(scenarios_found) == 7
    assert scenarios_found == set(SCENARIO_GENERATORS.keys())


def test_trace_schema_validation():
    """Verify all generated traces satisfy schema validation rules."""
    dataset = generate_dataset(n_per_scenario=3, seed=456)
    for trace in dataset:
        trace_dict = trace.to_dict()
        is_valid, errors = validate_trace(trace_dict)
        assert is_valid, f"Validation failed for trace {trace.trace_id}: {errors}"


def test_malicious_and_benign_pivot_steps():
    """Verify pivot_step rules: malicious must have valid int, benign must be None."""
    dataset = generate_dataset(n_per_scenario=2, seed=789)
    for trace in dataset:
        if trace.label == "malicious":
            assert trace.pivot_step is not None
            assert 0 <= trace.pivot_step < len(trace.events)
            # Verify pivot event is a webhook call
            pivot_event = trace.events[trace.pivot_step]
            assert pivot_event.server == "webhook"
            assert pivot_event.tool == "post_to_webhook"
        else:
            assert trace.label == "benign"
            assert trace.pivot_step is None


def test_schema_validator_rejections():
    """Verify that invalid/corrupted traces are properly rejected by schema validator."""
    # Test 1: Missing trace_id
    bad_trace_1 = {"label": "benign", "objective": "benign", "pivot_step": None, "events": []}
    is_valid, errors = validate_trace(bad_trace_1)
    assert not is_valid
    assert any("trace_id" in err for err in errors)

    # Test 2: Benign trace with non-null pivot_step
    bad_trace_2 = {
        "trace_id": "test-1",
        "label": "benign",
        "objective": "benign",
        "pivot_step": 1,
        "events": [{"step": 0, "timestamp": "2026-01-01T00:00:00", "server": "filesystem", "tool": "read", "args": {}, "args_entities": []}],
    }
    is_valid, errors = validate_trace(bad_trace_2)
    assert not is_valid
    assert any("pivot_step = None" in err for err in errors)

    # Test 3: Malicious trace with out of bounds pivot_step
    bad_trace_3 = {
        "trace_id": "test-2",
        "label": "malicious",
        "objective": "credential_exfiltration",
        "pivot_step": 10,  # Out of bounds
        "events": [{"step": 0, "timestamp": "2026-01-01T00:00:00", "server": "filesystem", "tool": "read", "args": {}, "args_entities": []}],
    }
    is_valid, errors = validate_trace(bad_trace_3)
    assert not is_valid
    assert any("out of bounds" in err for err in errors)


def test_save_and_read_traces():
    """Verify trace saving to disk and JSONL formatting."""
    temp_dir = tempfile.mkdtemp()
    try:
        dataset = generate_dataset(n_per_scenario=1, seed=999)
        saved_paths = save_dataset_to_dir(dataset, output_dir=temp_dir)
        assert len(saved_paths) == 7

        for path in saved_paths:
            assert os.path.exists(path)
            with open(path, "r", encoding="utf-8") as f:
                lines = [json.loads(line) for line in f.readlines()]
                assert len(lines) >= 3  # Header + at least 1 event + Footer
                assert lines[0]["type"] == "header"
                assert lines[-1]["type"] == "footer"
                assert lines[-1]["total_events"] == len(lines) - 2
    finally:
        shutil.rmtree(temp_dir)
