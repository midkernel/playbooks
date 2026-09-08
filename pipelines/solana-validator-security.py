#!/usr/bin/env python3
"""Agave / jito-solana-class Scan playbook as a native agentflow graph."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _midkernel import emit  # noqa: E402

emit(
    "solana-validator-security",
    description=(
        "Outcome-first validator-client security review (Agave / jito-solana-class) "
        "as a Kimi + OpenRouter agentflow graph. Default clone "
        "midkernel/bounty-target-jito-solana@master. Same Midkernel-dev ECS target "
        "and report.md artifact contract as security-review."
    ),
)
