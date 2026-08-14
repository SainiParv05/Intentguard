"""
generator/schema_validator.py

Provides validation logic for IntentGuard trace structures to ensure trace formatting,
step ordering, server classifications, and ground-truth pivot step labels comply with
the IntentBench-Lite dataset specification.
"""

from typing import Any, Dict, List, Tuple


VALID_LABELS = {"benign", "malicious"}
VALID_OBJECTIVES = {
    "credential_exfiltration",
    "data_exfiltration",
    "recon_only",
    "benign",
}
VALID_SERVERS = {"filesystem", "webhook"}


def validate_event(event: Dict[str, Any], step_index: int) -> List[str]:
    """Validates a single event dictionary within a trace."""
    errors = []
    
    if "step" not in event:
        errors.append(f"Event at index {step_index} missing 'step' field")
    elif event["step"] != step_index:
        errors.append(f"Event step mismatch: expected {step_index}, got {event['step']}")
        
    if "timestamp" not in event or not isinstance(event["timestamp"], str):
        errors.append(f"Event at step {step_index} missing valid ISO8601 string 'timestamp'")
        
    if "server" not in event or event["server"] not in VALID_SERVERS:
        errors.append(
            f"Event at step {step_index} invalid 'server': {event.get('server')}. Must be one of {VALID_SERVERS}"
        )
        
    if "tool" not in event or not isinstance(event["tool"], str):
        errors.append(f"Event at step {step_index} missing valid string 'tool'")
        
    if "args" not in event or not isinstance(event["args"], dict):
        errors.append(f"Event at step {step_index} missing dict 'args'")
        
    if "args_entities" not in event or not isinstance(event["args_entities"], list):
        errors.append(f"Event at step {step_index} missing list 'args_entities'")
        
    return errors


def validate_trace(trace: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validates a trace dictionary against the IntentGuard trace schema.
    Returns (is_valid, list_of_error_strings).
    """
    errors = []
    
    required_fields = ["trace_id", "label", "objective", "pivot_step", "events"]
    for field in required_fields:
        if field not in trace:
            errors.append(f"Trace missing required top-level field: '{field}'")
            
    if errors:
        return False, errors

    if trace["label"] not in VALID_LABELS:
        errors.append(f"Invalid label '{trace['label']}'. Must be one of {VALID_LABELS}")

    if trace["objective"] not in VALID_OBJECTIVES:
        errors.append(f"Invalid objective '{trace['objective']}'. Must be one of {VALID_OBJECTIVES}")

    pivot = trace["pivot_step"]
    events = trace["events"]

    if trace["label"] == "benign":
        if pivot is not None:
            errors.append(f"Benign trace must have pivot_step = None, got {pivot}")
    elif trace["label"] == "malicious":
        if pivot is None:
            errors.append("Malicious trace must have a non-null pivot_step integer")
        elif not isinstance(pivot, int) or pivot < 0 or pivot >= len(events):
            errors.append(f"Malicious trace pivot_step {pivot} out of bounds for event count {len(events)}")

    if not isinstance(events, list) or len(events) == 0:
        errors.append("Trace 'events' must be a non-empty list")
    else:
        for idx, ev in enumerate(events):
            ev_errors = validate_event(ev, idx)
            errors.extend(ev_errors)

    return (len(errors) == 0), errors
