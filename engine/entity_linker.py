"""
engine/entity_linker.py

Entity Extraction & NLP Linker Engine for IntentGuard CTAG.
Extracts sensitive keywords, file paths, Base64 payloads, SQL columns, IP/URLs, and tokens
from tool invocation outputs and inputs to establish cross-MCP transitive entity edges.
Includes VULN-04 protection against unbounded input payload sizes.
"""

import base64
import json
import re
from typing import Any, Dict, Set, Union

SENSITIVE_KEYWORDS = {
    "env",
    "secret",
    "ssh_key",
    "id_rsa",
    "credential",
    "password",
    "token",
    "aws_access_key",
    "private_key",
    "api_key",
    "db_pass",
}

PATH_PATTERNS = re.compile(r"[\w\-\./]+\.(?:json|yml|yaml|txt|md|py|sh|env|rsa|conf|config)")
BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{8,}={0,2}")
STOP_WORDS = {"ok", "http", "https", "true", "false", "path", "url", "data", "file", "text", "test", "build", "status", "passed"}


def decode_base64_payloads(text: str) -> Set[str]:
    """
    Identifies Base64 encoded substrings within text, decodes them,
    and extracts inner tokens.
    """
    tokens = set()
    matches = BASE64_PATTERN.findall(text)
    for m in matches:
        if m.isalpha() and m.islower() and len(m) < 12:
            continue
        try:
            decoded_bytes = base64.b64decode(m)
            decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
            if any(c.isalnum() for c in decoded_str) and len(decoded_str) > 3:
                decoded_lower = decoded_str.lower()
                tokens.add(decoded_lower)
                normalized_text = decoded_lower.replace("_", " ").replace("-", " ")
                inner_words = set(re.findall(r"\b[a-zA-Z_0-9]{3,}\b", normalized_text))
                tokens.update(inner_words - STOP_WORDS)
        except Exception:
            pass
    return tokens


def extract_entities(data: Union[str, Dict[str, Any]]) -> Set[str]:
    """
    Extracts normalized entity tokens (keywords, file path stems, secrets, Base64 decoded payloads)
    from a string or nested dictionary structure.
    """
    if isinstance(data, dict):
        text_parts = []
        def _flatten(obj):
            if isinstance(obj, dict):
                for k, v in obj.items():
                    text_parts.append(str(k))
                    _flatten(v)
            elif isinstance(obj, list):
                for item in obj:
                    _flatten(item)
            else:
                text_parts.append(str(obj))
        _flatten(data)
        text = " ".join(text_parts)
    else:
        text = str(data or "")

    # VULN-04 Mitigation: Cap max input length to 50KB to prevent ReDoS on massive inputs
    if len(text) > 50000:
        text = text[:50000]

    text_lower = text.lower()
    entities = set()

    # 1. Sensitive keyword matching
    for kw in SENSITIVE_KEYWORDS:
        if kw in text_lower:
            entities.add(kw)

    # 2. File path & stem extraction
    paths = PATH_PATTERNS.findall(text)
    for p in paths:
        p_lower = p.lower()
        entities.add(p_lower)
        filename = p_lower.split("/")[-1].split("\\")[-1]
        entities.add(filename)
        stem = filename.split(".")[0]
        if stem and len(stem) > 2:
            entities.add(stem)

    # 3. Word tokenization
    word_tokens = set(re.findall(r"\b[a-zA-Z_0-9]{3,}\b", text_lower))
    entities.update(word_tokens - STOP_WORDS)

    # 4. Base64 payload decoding
    entities.update(decode_base64_payloads(text))

    return entities


def compute_entity_overlap(result_str: str, args_dict: Dict[str, Any]) -> float:
    """
    Computes a cross-MCP entity overlap weight in [0.0, 1.0] between a prior tool's
    result_preview and a subsequent tool's argument dictionary.
    """
    res_entities = extract_entities(result_str)
    args_entities = extract_entities(args_dict)

    if not res_entities or not args_entities:
        return 0.0

    intersection = res_entities.intersection(args_entities) - STOP_WORDS
    filtered_intersection = {e for e in intersection if len(e) > 2 and not e.isdigit()}

    if not filtered_intersection:
        return 0.0

    score = len(filtered_intersection) * 0.4
    return min(score, 1.0)
