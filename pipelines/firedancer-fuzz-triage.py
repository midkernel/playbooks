#!/usr/bin/env python3
"""FireBAM / Firedancer-class fuzz triage as a native agentflow graph."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _midkernel import emit  # noqa: E402

emit(
    "firedancer-fuzz-triage",
    description=(
        "Patch-oriented sanitizer and fuzz-crash triage for FireBAM / Firedancer-class "
        "C/C++ clients as a Kimi + OpenRouter agentflow graph. Same Midkernel-dev ECS "
        "target and report.md artifact contract as security-review."
    ),
)
