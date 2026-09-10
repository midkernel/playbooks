#!/usr/bin/env python3
"""Trail of Bits–style /goal Scan playbook as a native agentflow graph.

App / runner start this file with ``agentflow run pipelines/goal-security-review.py``.
Stdout is PipelineSpec JSON (required by the agentflow loader).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from _midkernel import emit_goal  # noqa: E402

emit_goal(
    "goal-security-review",
    description=(
        "Trail of Bits–style /goal security hunt: clone the target GitHub repo, "
        "write THREAT_MODEL.md, author GOAL_COUNT (default 6) outcome prompts, "
        "run hunter-1..N in parallel (default concurrency=2, GOAL_CONCURRENCY "
        "picker 1|2|4|6; siblings of surface-split; "
        "hunters wrap to graph COMPLETED so judge-a depends_on every hunter; "
        "a hunter timeout does not fail the GOAL run), "
        "dual-pass OpenRouter judges, "
        "write report.md, upload per-node I/O plus "
        "s3://midkernel-dev-artifacts/runs/<RUN_ID>/report.md. "
        "Kimi CLI via OpenRouter on Midkernel-dev ECS. No known-issues / GitHub dedupe."
    ),
)
