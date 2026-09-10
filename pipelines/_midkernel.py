"""Shared Midkernel agentflow helpers.

Used by ``pipelines/*.py``. This file is not a pipeline (no Graph, no JSON
on stdout). ``list_playbooks`` does not walk ``pipelines/``.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    from ._node_io import (  # type: ignore[import-not-found]
        DEFAULT_KIMI_MAX_TOKENS,
        MAX_SAFE_KIMI_MAX_TOKENS,
        MAX_TOKENS_ENV_NAMES,
        UNSAFE_OPENROUTER_MAX_TOKENS,
        bootstrap_run_io,
        clamp_kimi_max_tokens,
        kimi_config_file,
        kimi_executable,
        kimi_io_env,
        kimi_max_tokens,
        openrouter_passthrough_env,
        render_kimi_openrouter_config,
        shell_io_env,
        wrap_shell_script,
    )
except ImportError:  # ``python3 pipelines/<slug>.py`` puts this dir on sys.path
    from _node_io import (  # type: ignore[import-not-found]
        DEFAULT_KIMI_MAX_TOKENS,
        MAX_SAFE_KIMI_MAX_TOKENS,
        MAX_TOKENS_ENV_NAMES,
        UNSAFE_OPENROUTER_MAX_TOKENS,
        bootstrap_run_io,
        clamp_kimi_max_tokens,
        kimi_config_file,
        kimi_executable,
        kimi_io_env,
        kimi_max_tokens,
        openrouter_passthrough_env,
        render_kimi_openrouter_config,
        shell_io_env,
        wrap_shell_script,
    )

# ---------------------------------------------------------------------------
# Midkernel-dev ECS (existing infra — do not invent VPC / SG / IAM)
# IDs match midkernel/app AGENTFLOW_DEV_DEFAULTS and midkernel/infra outputs.
# ---------------------------------------------------------------------------

AWS_ACCOUNT = "489470371031"
AWS_REGION = "us-east-1"
ECS_CLUSTER = "midkernel-dev"
ECS_SUBNETS = (
    "subnet-0f93686b81d5d8d7d",
    "subnet-08ae98ea51ce9ccd7",
)
ECS_SECURITY_GROUP = "sg-015a103caabc861d0"
AGENT_IMAGE = f"{AWS_ACCOUNT}.dkr.ecr.{AWS_REGION}.amazonaws.com/midkernel-agentflow-agents:latest"
EXECUTION_ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT}:role/midkernel-dev-ecsTaskExecutionRole"
TASK_ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT}:role/midkernel-dev-ecsTaskRole"
CONTROL_PLANE_ROLE_ARN = f"arn:aws:iam::{AWS_ACCOUNT}:role/midkernel-dev-agentflow-control-plane"
LOG_GROUP = "/agentflow"
ARTIFACTS_BUCKET = "midkernel-dev-artifacts"
ARTIFACTS_PREFIX = "runs/"
REPORT_NAME = "report.md"
OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
# Fallback only. App SCAN_MODEL_BY_PROFILE injects OPENROUTER_MODEL / MODEL
# per Scan profile. Balanced Pareto Scan preset is the documented default.
DEFAULT_OPENROUTER_MODEL = "google/gemini-3.8-flash"
DEFAULT_PLAYBOOKS_REPO = "https://github.com/midkernel/playbooks"
DEFAULT_GOAL_COUNT = 6
MAX_GOAL_HUNTERS = 6
DEFAULT_JUDGE_B_MODEL = "anthropic/claude-sonnet-4.5"
DEFAULT_JUDGE_B_FALLBACK = "openai/gpt-4o"
GOAL_HUNTER_IDS = tuple(f"hunter-{n}" for n in range(1, MAX_GOAL_HUNTERS + 1))
THREAT_MODEL_NAME = "THREAT_MODEL.md"
GOALS_MANIFEST = "goals/MANIFEST.md"
VALIDATED_A_MANIFEST = "findings/validated-a/MANIFEST.md"
VALIDATED_B_MANIFEST = "findings/validated-b/MANIFEST.md"


@dataclass(frozen=True)
class DefaultTarget:
    """Playbook default clone when GITHUB_OWNER / GITHUB_NAME / GITHUB_REF are unset."""

    owner: str
    name: str
    ref: str

    @property
    def repo(self) -> str:
        return f"{self.owner}/{self.name}"


# Hunt-only private mirrors. security-review has no default — caller supplies owner/name.
DEFAULT_TARGETS: dict[str, DefaultTarget] = {
    "solana-validator-security": DefaultTarget(
        owner="midkernel",
        name="bounty-target-jito-solana",
        ref="master",
    ),
    "firedancer-fuzz-triage": DefaultTarget(
        owner="midkernel",
        name="bounty-target-jito-firebam",
        ref="main",
    ),
}

# App container env (midkernel/app src/lib/agentflow-contract.ts).
AGENT_ENV_APP = (
    "RUN_ID",
    "GITHUB_OWNER",
    "GITHUB_NAME",
    "PLAYBOOK",
    "PROFILE",
    "THREAT",
    "ARTIFACTS_BUCKET",
    "ARTIFACTS_PREFIX",
    "ARTIFACTS_KEY",
    "MODEL",
    "OPENROUTER_MODEL",
)

# Runner aliases (midkernel/runner). Accept both until siblings converge.
AGENT_ENV_RUNNER_ALIASES = {
    "PLAYBOOK": ("PLAYBOOK_SLUG",),
    "PROFILE": ("SCAN_PROFILE",),
    "THREAT": ("THREAT_PIN",),
}

PROFILE_FARGATE = {
    "low": {"cpu": "1024", "memory": "2048"},
    "balanced": {"cpu": "2048", "memory": "4096"},
    "max": {"cpu": "4096", "memory": "8192"},
}

# Per-node kimi budget (GOAL hunters/judges use this table).
# QA cmtutkn8k0003id04hs5s8j7z (low): hunter-1 exit 124 after 900s.
# Match former balanced node budget. Keep lockstep with runner.
PROFILE_TIMEOUT_SECONDS = {
    "low": 30 * 60,
    "balanced": 30 * 60,
    "max": 60 * 60,
}

_FRONTMATTER = re.compile(r"^---\r?\n[\s\S]*?\r?\n---\r?\n?")


def workspace_root() -> Path:
    return Path(__file__).resolve().parent.parent


def workdir() -> str:
    return os.environ.get("WORKDIR", "/workspace").rstrip("/") or "/workspace"


def repo_dir() -> str:
    return os.path.join(workdir(), "repo")


def outputs_dir() -> str:
    return os.environ.get("OUTPUTS_DIR", "/outputs").rstrip("/") or "/outputs"


def env_first(*names: str, default: str = "") -> str:
    for name in names:
        value = (os.environ.get(name) or "").strip()
        if value:
            return value
    return default


def scan_profile() -> str:
    profile = env_first("PROFILE", "SCAN_PROFILE", default="balanced").lower()
    return profile if profile in PROFILE_FARGATE else "balanced"


def normalize_openrouter_model(raw: str, *, default: str = DEFAULT_OPENROUTER_MODEL) -> str:
    slug = (raw or "").strip()
    if slug.startswith("openrouter/"):
        slug = slug[len("openrouter/") :]
    if "/" not in slug:
        return default
    return slug


def openrouter_model() -> str:
    raw = env_first("OPENROUTER_MODEL", "MODEL", default=DEFAULT_OPENROUTER_MODEL)
    return normalize_openrouter_model(raw, default=DEFAULT_OPENROUTER_MODEL)


def goal_count() -> int:
    """How many hunter-* nodes to emit (default 6, max 6). First-class dynamic nodes."""
    raw = env_first("GOAL_COUNT", default=str(DEFAULT_GOAL_COUNT))
    try:
        value = int(raw)
    except ValueError:
        return DEFAULT_GOAL_COUNT
    return max(1, min(value, MAX_GOAL_HUNTERS))


def judge_a_model() -> str:
    raw = env_first("JUDGE_A_MODEL")
    if raw:
        return normalize_openrouter_model(raw, default=openrouter_model())
    return openrouter_model()


def judge_b_model() -> str:
    """Different OpenRouter model than judge-a unless JUDGE_B_MODEL is set explicitly."""
    raw = env_first("JUDGE_B_MODEL")
    if raw:
        return normalize_openrouter_model(raw, default=DEFAULT_JUDGE_B_MODEL)
    candidate = DEFAULT_JUDGE_B_MODEL
    if candidate == judge_a_model():
        return DEFAULT_JUDGE_B_FALLBACK
    return candidate


def artifact_key(run_id: str | None = None) -> str:
    """Final assemble object: ``runs/<RUN_ID>/report.md`` (unchanged).

    Live Run UI objects (see ``pipelines/_node_io.py``) sit next to it::

        runs/<RUN_ID>/graph.json
        runs/<RUN_ID>/nodes/<nodeId>/prompt.md
        runs/<RUN_ID>/nodes/<nodeId>/output.md
        runs/<RUN_ID>/nodes/<nodeId>/meta.json
    """
    rid = (run_id or env_first("RUN_ID") or "<RUN_ID>").strip()
    prefix = env_first("ARTIFACTS_PREFIX", default=ARTIFACTS_PREFIX)
    prefix = prefix.strip().strip("/") or "runs"
    return f"{prefix}/{rid}/{REPORT_NAME}"


def artifact_uri(run_id: str | None = None) -> str:
    bucket = env_first("ARTIFACTS_BUCKET", default=ARTIFACTS_BUCKET)
    return f"s3://{bucket}/{artifact_key(run_id)}"
