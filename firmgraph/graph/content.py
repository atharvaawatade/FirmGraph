"""Content addressing: a node's identity IS the hash of its canonical content.

Same firmware in -> same node ids out -> diff is a set operation and
reproducibility is testable. This module is the determinism guarantee;
keep it boring and side-effect free.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(content: dict[str, Any]) -> str:
    """Canonical form: sorted keys, compact separators, no NaN, UTF-8."""
    return json.dumps(content, sort_keys=True, separators=(",", ":"), allow_nan=False)


def node_id(kind: str, content: dict[str, Any]) -> str:
    payload = kind + "\x00" + canonical_json(content)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
