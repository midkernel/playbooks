#!/usr/bin/env python3
"""Midkernel Scan default playbook as a native agentflow graph.

App / runner start this file with ``agentflow run pipelines/security-review.py``.
Stdout is PipelineSpec JSON (required by the agentflow loader).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _midkernel import emit  # noqa: E402

emit(
    "security-review",
    description=(
        "Default Midkernel Scan graph: clone the target GitHub repo, run a Kimi CLI "
        "security review via OpenRouter, write report.md, upload to "
        "s3://midkernel-dev-artifacts/runs/<RUN_ID>/report.md."
    ),
)
