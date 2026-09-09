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
DEFAULT_OPENROUTER_MODEL = "moonshotai/kimi-k3"
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

PROFILE_TIMEOUT_SECONDS = {
    "low": 15 * 60,
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


def playbook_prompt(slug: str) -> str:
    path = workspace_root() / f"{slug}.md"
    text = path.read_text(encoding="utf-8").replace("\ufeff", "")
    text = text.lstrip()
    match = _FRONTMATTER.match(text)
    if match:
        text = text[match.end() :]
    body = text.strip()
    if not body:
        raise ValueError(f"playbook {slug}.md has an empty prompt body")
    return body


def agentflow_target_mode() -> str:
    """``ecs`` (default, published graph) or ``local`` (in-task execution)."""
    raw = env_first("MIDKERNEL_AGENTFLOW_TARGET", default="ecs").lower()
    return "local" if raw in {"local", "in-task", "task"} else "ecs"


def midkernel_ecs_target(*, profile: str | None = None) -> dict[str, Any]:
    """Explicit Midkernel-dev Fargate target. Never omit subnets/SG (zero-config)."""
    sizes = PROFILE_FARGATE[profile or scan_profile()]
    return {
        "kind": "ecs",
        "region": AWS_REGION,
        "cluster": ECS_CLUSTER,
        "image": AGENT_IMAGE,
        "cpu": sizes["cpu"],
        "memory": sizes["memory"],
        "subnets": list(ECS_SUBNETS),
        "security_groups": [ECS_SECURITY_GROUP],
        "assign_public_ip": True,
        "install_agents": ["kimi"],
        "shared": "midkernel-scan",
    }


def node_target(*, cwd: str | None = None) -> dict[str, Any]:
    if agentflow_target_mode() == "local":
        target: dict[str, Any] = {"kind": "local"}
        if cwd:
            target["cwd"] = cwd
        return target
    return midkernel_ecs_target()


def openrouter_provider() -> dict[str, Any]:
    """Kimi CLI via OpenRouter ``openai_legacy`` (not Moonshot, not Bedrock)."""
    return {
        "name": "openrouter",
        "base_url": OPENROUTER_BASE_URL,
        "api_key_env": "OPENROUTER_API_KEY",
        "env": {
            "OPENAI_BASE_URL": OPENROUTER_BASE_URL,
        },
    }


def openrouter_node_env(*, model: str | None = None) -> dict[str, str]:
    """OpenRouter env baked onto every Kimi node (review + emit_goal).

    ``BASH_ENV=/dev/null`` skips runner ``prepare_node``, so keys / HOME /
    ``KIMI_SHARE_DIR`` must live on the node env, not only the parent process.
    """
    return openrouter_passthrough_env(model=model or openrouter_model())


def kimi_openrouter_config(model: str | None = None) -> str:
    return render_kimi_openrouter_config(
        model or openrouter_model(),
        max_tokens=kimi_max_tokens(),
    )


def kimi_extra_args(model: str | None = None) -> list[str]:
    """``--config`` must be a file path. agentflow appends extra_args verbatim.

    Inline TOML (the old value) made kimi.bin print ``LLM not set`` on
    review / threat-model after prepare succeeded.
    """
    del model  # path is shared; wrap_kimi rewrites the file per-node model
    return ["--config", str(kimi_config_file())]


def default_target(slug: str) -> DefaultTarget | None:
    return DEFAULT_TARGETS.get(slug)


def review_prompt(slug: str) -> str:
    skill = playbook_prompt(slug)
    dest = artifact_uri()
    target = default_target(slug)
    if target:
        clone_line = (
            f"- Default clone for this playbook is the private hunt mirror "
            f"github.com/{target.repo} at ref `{target.ref}` "
            f"(overridable via GITHUB_OWNER, GITHUB_NAME, GITHUB_REF). "
            f"If the tree is not already at {repo_dir()}, clone it with GITHUB_TOKEN "
            "(https://x-access-token:<token>@github.com/<owner>/<name>.git). "
            "Shallow clone only — do not recurse submodules "
            "(Firedancer `agave/` is out of scope unless the crash stack lands there)."
        )
    else:
        clone_line = (
            f"- Clone of github.com/${{GITHUB_OWNER}}/${{GITHUB_NAME}} if already present "
            f"at {repo_dir()}, otherwise clone it with GITHUB_TOKEN "
            "(https://x-access-token:<token>@github.com/<owner>/<name>.git), "
            "optional GITHUB_REF as --branch. This playbook has no default target."
        )
    return (
        f"{skill}\n\n"
        "You are Midkernel Scan running as the Kimi CLI harness on OpenRouter only "
        "(not Bedrock, not AI Gateway). OpenCode is not part of this path.\n\n"
        "Workspace:\n"
        f"{clone_line}\n"
        f"- Read RUN_ID, PLAYBOOK/PLAYBOOK_SLUG, PROFILE/SCAN_PROFILE, "
        "THREAT/THREAT_PIN from the environment. If THREAT is non-empty, "
        "prioritize that pin; it is not a fourth profile.\n"
        "- Hunt only: no bounty-submit, disclosure-program, or Immunefi filing language.\n\n"
        "Write the real review or triage to "
        f"**{REPORT_NAME}** in the workspace root of the cloned repo "
        f"(also copy it to {outputs_dir()}/{REPORT_NAME} if that directory exists).\n\n"
        "The Midkernel control plane uploads that file to "
        f"`{dest}` (s3://$ARTIFACTS_BUCKET/$ARTIFACTS_PREFIX$RUN_ID/{REPORT_NAME}).\n\n"
        "Report requirements:\n"
        "- Follow the playbook skill body above for output shape.\n"
        "- No stub, placeholder, lorem ipsum, or \"report coming soon\" text. "
        "If the tree is clean or every crash is harness/invalid-input, say so "
        "with evidence of what you read.\n"
    )


PREPARE_SCRIPT_TEMPLATE = r"""
set -euo pipefail
WORKDIR="${WORKDIR:-/workspace}"
OUTPUTS_DIR="${OUTPUTS_DIR:-/outputs}"
REPO_DIR="${WORKDIR}/repo"
PLAYBOOK="${PLAYBOOK:-${PLAYBOOK_SLUG:-__PLAYBOOK_SLUG__}}"
PROFILE="${PROFILE:-${SCAN_PROFILE:-balanced}}"
THREAT="${THREAT:-${THREAT_PIN:-}}"
ARTIFACTS_BUCKET="${ARTIFACTS_BUCKET:-midkernel-dev-artifacts}"
ARTIFACTS_PREFIX="${ARTIFACTS_PREFIX:-runs/}"
OPENROUTER_MODEL="${OPENROUTER_MODEL:-${MODEL:-moonshotai/kimi-k3}}"
# First-wins order matches runner: MIDKERNEL_OPENROUTER_MAX_TOKENS,
# OPENROUTER_MAX_TOKENS, KIMI_MAX_TOKENS, KIMI_MODEL_MAX_TOKENS,
# KIMI_MODEL_MAX_COMPLETION_TOKENS.
KIMI_MAX_TOKENS="${MIDKERNEL_OPENROUTER_MAX_TOKENS:-${OPENROUTER_MAX_TOKENS:-${KIMI_MAX_TOKENS:-${KIMI_MODEL_MAX_TOKENS:-${KIMI_MODEL_MAX_COMPLETION_TOKENS:-__KIMI_MAX_TOKENS__}}}}}"
OPENROUTER_SECRET_ID="${OPENROUTER_SECRET_ID:-midkernel/dev/harness/openrouter-api-key}"
GITHUB_TOKEN_SECRET_ID="${GITHUB_TOKEN_SECRET_ID:-midkernel/dev/harness/github-token}"
AWS_REGION="${AWS_REGION:-us-east-1}"
__DEFAULT_CLONE__
: "${RUN_ID:?RUN_ID is required}"
: "${GITHUB_OWNER:?GITHUB_OWNER is required (no default target for this playbook)}"
: "${GITHUB_NAME:?GITHUB_NAME is required (no default target for this playbook)}"

case "$OPENROUTER_MODEL" in
  openrouter/*) OPENROUTER_MODEL="${OPENROUTER_MODEL#openrouter/}" ;;
esac
# 0 / non-numeric would disable kimi-cli's clamp and restore the catalog default.
# Hard ceiling 65536. 131072 is the exact 402 reservation — never a valid opt-in.
case "$KIMI_MAX_TOKENS" in
  ''|*[!0-9]*|0) KIMI_MAX_TOKENS="__KIMI_MAX_TOKENS__" ;;
esac
# Values >=131072 or otherwise above 65536 become the 32768 default.
if [ "$KIMI_MAX_TOKENS" -gt 65536 ] 2>/dev/null; then
  KIMI_MAX_TOKENS="__KIMI_MAX_TOKENS__"
fi
export KIMI_MAX_TOKENS
export OPENROUTER_MAX_TOKENS="$KIMI_MAX_TOKENS"
export MIDKERNEL_OPENROUTER_MAX_TOKENS="$KIMI_MAX_TOKENS"
export KIMI_MODEL_MAX_COMPLETION_TOKENS="$KIMI_MAX_TOKENS"
export KIMI_MODEL_MAX_TOKENS="$KIMI_MAX_TOKENS"

export WORKDIR
export OUTPUTS_DIR
mkdir -p "$WORKDIR" "$OUTPUTS_DIR" "$HOME/.kimi" "$WORKDIR/.midkernel" "$WORKDIR/.midkernel/kimi"
export MIDKERNEL_NODE_IO="${MIDKERNEL_NODE_IO:-1}"
export BASH_ENV=/dev/null
export MIDKERNEL_NODE_READY=1
export KIMI_SHARE_DIR="${KIMI_SHARE_DIR:-$WORKDIR/.midkernel/kimi}"
if [ -x /opt/midkernel/kimi.bin ]; then
  export MIDKERNEL_KIMI_BIN="${MIDKERNEL_KIMI_BIN:-/opt/midkernel/kimi.bin}"
  export KIMI_REAL_BIN="${KIMI_REAL_BIN:-$MIDKERNEL_KIMI_BIN}"
fi
echo "node io: prepare WORKDIR=$WORKDIR RUN_ID=${RUN_ID:-unset} MIDKERNEL_NODE_IO=$MIDKERNEL_NODE_IO MIDKERNEL_AGENTFLOW_TARGET=${MIDKERNEL_AGENTFLOW_TARGET:-} MIDKERNEL_KIMI_BIN=${MIDKERNEL_KIMI_BIN:-unset}" >&2

python3 - "$OPENROUTER_SECRET_ID" "$GITHUB_TOKEN_SECRET_ID" "$AWS_REGION" <<'PY'
import json, os, sys

def load_secret(secret_id: str, region: str) -> str:
    try:
        import boto3
    except ImportError:
        return ""
    try:
        raw = boto3.client("secretsmanager", region_name=region).get_secret_value(
            SecretId=secret_id
        ).get("SecretString") or ""
    except Exception as exc:
        print(f"secretsmanager get failed for {secret_id}: {exc}", file=sys.stderr)
        return ""
    raw = raw.strip()
    if not raw:
        return ""
    if raw.startswith("{"):
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return raw
        for key in (
            "apiKey", "api_key", "OPENROUTER_API_KEY", "key",
            "token", "github_token", "GITHUB_TOKEN", "installationToken",
        ):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return ""
    return raw

secret_id, gh_secret_id, region = sys.argv[1], sys.argv[2], sys.argv[3]
workdir = os.environ.get("WORKDIR", "/workspace")
if not os.environ.get("OPENROUTER_API_KEY", "").strip() and os.environ.get("MIDKERNEL_LOCAL") != "1":
    value = load_secret(secret_id, region)
    if value:
        for dest in (
            os.path.join(os.environ.get("HOME", "/home/agent"), ".midkernel-openrouter"),
            os.path.join(workdir, ".midkernel-openrouter"),
        ):
            print(value, file=open(dest, "w"))
if not os.environ.get("GITHUB_TOKEN", "").strip() and os.environ.get("MIDKERNEL_LOCAL") != "1":
    value = load_secret(gh_secret_id, region)
    if value:
        print(value, file=open(os.environ["HOME"] + "/.midkernel-github", "w"))
PY

if [ -z "${OPENROUTER_API_KEY:-}" ] && [ -f "$WORKDIR/.midkernel-openrouter" ]; then
  OPENROUTER_API_KEY="$(tr -d '\n' < "$WORKDIR/.midkernel-openrouter")"
  export OPENROUTER_API_KEY
fi
if [ -z "${OPENROUTER_API_KEY:-}" ] && [ -f "$HOME/.midkernel-openrouter" ]; then
  OPENROUTER_API_KEY="$(tr -d '\n' < "$HOME/.midkernel-openrouter")"
  export OPENROUTER_API_KEY
fi
if [ -z "${GITHUB_TOKEN:-}" ] && [ -f "$HOME/.midkernel-github" ]; then
  GITHUB_TOKEN="$(tr -d '\n' < "$HOME/.midkernel-github")"
  export GITHUB_TOKEN
fi

if [ -z "${OPENROUTER_API_KEY:-}" ]; then
  echo "OPENROUTER_API_KEY is missing (set env or Secrets Manager midkernel/dev/harness/openrouter-api-key)" >&2
  exit 2
fi
export OPENAI_API_KEY="$OPENROUTER_API_KEY"
export KIMI_API_KEY="$OPENROUTER_API_KEY"
export OPENAI_BASE_URL="https://openrouter.ai/api/v1"

# Persist key + config on the shared task disk. Later Kimi nodes run with
# cwd=$WORKDIR/repo and BASH_ENV=/dev/null (runner prepare_node skipped),
# so $HOME/.kimi/config.toml alone is not enough.
printf '%s' "$OPENROUTER_API_KEY" > "$WORKDIR/.midkernel-openrouter"
chmod 600 "$WORKDIR/.midkernel-openrouter" || true
if [ -n "${HOME:-}" ]; then
  printf '%s' "$OPENROUTER_API_KEY" > "$HOME/.midkernel-openrouter"
  chmod 600 "$HOME/.midkernel-openrouter" || true
fi

cat > "$KIMI_SHARE_DIR/config.toml" <<EOF
default_model = "midkernel"
default_thinking = false
default_yolo = true

[providers.openrouter]
type = "openai_legacy"
base_url = "https://openrouter.ai/api/v1"
api_key = "${OPENROUTER_API_KEY}"

[models.midkernel]
provider = "openrouter"
model = "${OPENROUTER_MODEL}"
max_context_size = 262144
max_tokens = ${KIMI_MAX_TOKENS}
max_output_size = ${KIMI_MAX_TOKENS}
EOF
chmod 600 "$KIMI_SHARE_DIR/config.toml" || true
cp "$KIMI_SHARE_DIR/config.toml" "$HOME/.kimi/config.toml"
chmod 600 "$HOME/.kimi/config.toml" || true

if [ ! -d "$REPO_DIR/.git" ]; then
  if [ -z "${GITHUB_TOKEN:-}" ]; then
    echo "GITHUB_TOKEN is missing (set env or Secrets Manager midkernel/dev/harness/github-token)" >&2
    exit 2
  fi
  CLONE_URL="https://x-access-token:${GITHUB_TOKEN}@github.com/${GITHUB_OWNER}/${GITHUB_NAME}.git"
  rm -rf "$REPO_DIR"
  if [ -n "${GITHUB_REF:-}" ]; then
    git clone --depth 1 --no-recurse-submodules --branch "$GITHUB_REF" "$CLONE_URL" "$REPO_DIR"
  else
    git clone --depth 1 --no-recurse-submodules "$CLONE_URL" "$REPO_DIR"
  fi
fi

echo "prepared playbook=${PLAYBOOK} profile=${PROFILE} threat=${THREAT} repo=${GITHUB_OWNER}/${GITHUB_NAME} dest=s3://${ARTIFACTS_BUCKET}/${ARTIFACTS_PREFIX}${RUN_ID}/report.md"
"""


def prepare_script(slug: str) -> str:
    """Bake this graph's slug and optional default clone target into prepare."""
    target = default_target(slug)
    if target:
        default_clone = "\n".join(
            [
                f'GITHUB_OWNER="${{GITHUB_OWNER:-{target.owner}}}"',
                f'GITHUB_NAME="${{GITHUB_NAME:-{target.name}}}"',
                f'GITHUB_REF="${{GITHUB_REF:-{target.ref}}}"',
                "",
            ]
        )
    else:
        default_clone = ""
    return (
        PREPARE_SCRIPT_TEMPLATE.replace("__PLAYBOOK_SLUG__", slug)
        .replace("__DEFAULT_CLONE__", default_clone)
        .replace("__KIMI_MAX_TOKENS__", str(kimi_max_tokens()))
        .strip()
    )


def build_scan_graph(slug: str, *, description: str):
    """Build the prepare → Kimi review → S3 publish graph for a Scan playbook."""
    from agentflow import Graph, kimi, shell

    profile = scan_profile()
    model = openrouter_model()
    timeout = PROFILE_TIMEOUT_SECONDS[profile]
    prompt = review_prompt(slug)
    review_cwd = repo_dir() if agentflow_target_mode() == "local" else None

    with Graph(
        slug,
        description=description,
        working_dir=".",
        concurrency=1,
        fail_fast=True,
    ) as graph:
        prepare = shell(
            task_id="prepare",
            script=wrap_shell_script("prepare", prepare_script(slug), outputs=[]),
            env=shell_io_env("prepare"),
            timeout_seconds=10 * 60,
            target=node_target(),
        )
        review = kimi(
            task_id="review",
            prompt=prompt,
            model=model,
            tools="read_write",
            provider=openrouter_provider(),
            env={**openrouter_node_env(model=model), **kimi_io_env("review", outputs=[REPORT_NAME], model=model)},
            executable=kimi_executable(),
            extra_args=kimi_extra_args(model),
            timeout_seconds=timeout,
            retries=0,
            target=node_target(cwd=review_cwd),
            success_criteria=[
                {"kind": "file_exists", "path": REPORT_NAME},
                {"kind": "file_nonempty", "path": REPORT_NAME},
            ],
        )
        publish = shell(
            task_id="publish",
            script=wrap_shell_script("publish", PUBLISH_SCRIPT.strip(), outputs=[]),
            env=shell_io_env("publish"),
            timeout_seconds=5 * 60,
            target=node_target(cwd=review_cwd),
            success_criteria=[
                {"kind": "output_contains", "value": "uploaded s3://"},
            ],
        )
        prepare >> review >> publish
    return graph


def emit(slug: str, *, description: str) -> None:
    graph = build_scan_graph(slug, description=description)
    # No disk/S3 during validate; bootstrap is a no-op unless a run is live.
    bootstrap_run_io(graph.to_payload())
    print(graph.to_json())


def clone_instructions(slug: str) -> str:
    """Same clone wording as ``review_prompt`` so goal nodes share the workspace contract."""
    target = default_target(slug)
    if target:
        return (
            f"- Default clone for this playbook is the private hunt mirror "
            f"github.com/{target.repo} at ref `{target.ref}` "
            f"(overridable via GITHUB_OWNER, GITHUB_NAME, GITHUB_REF). "
            f"If the tree is not already at {repo_dir()}, clone it with GITHUB_TOKEN "
            "(https://x-access-token:<token>@github.com/<owner>/<name>.git). "
            "Shallow clone only — do not recurse submodules "
            "(Firedancer `agave/` is out of scope unless the crash stack lands there)."
        )
    return (
        f"- Clone of github.com/${{GITHUB_OWNER}}/${{GITHUB_NAME}} if already present "
        f"at {repo_dir()}, otherwise clone it with GITHUB_TOKEN "
        "(https://x-access-token:<token>@github.com/<owner>/<name>.git), "
        "optional GITHUB_REF as --branch. This playbook has no default target."
    )


def goal_workspace_preamble(slug: str) -> str:
    dest = artifact_uri()
    return (
        "You are Midkernel Scan running as the Kimi CLI harness on OpenRouter only "
        "(not Bedrock, not AI Gateway). OpenCode is not part of this path.\n\n"
        "Workspace:\n"
        f"{clone_instructions(slug)}\n"
        f"- Shared handoff is files under the cloned repo ({repo_dir()} when local). "
        "Read and write THREAT_MODEL.md, goals/, findings/, and report.md there.\n"
        f"- Read RUN_ID, PLAYBOOK/PLAYBOOK_SLUG, PROFILE/SCAN_PROFILE, "
        "THREAT/THREAT_PIN, GOAL_COUNT from the environment.\n"
        "- Hunt only: no bounty-submit, disclosure-program, or Immunefi filing language.\n"
        "- Do not search local known-findings files or open GitHub issues/PRs for "
        "duplicates. That dedupe step is out of scope for this playbook.\n"
        f"- Final artifact is **{REPORT_NAME}**. The control plane uploads it to `{dest}`.\n"
    )


def _file_criteria(*paths: str) -> list[dict[str, str]]:
    criteria: list[dict[str, str]] = []
    for path in paths:
        criteria.append({"kind": "file_exists", "path": path})
        criteria.append({"kind": "file_nonempty", "path": path})
    return criteria


def _kimi_scan_node(
    *,
    task_id: str,
    prompt: str,
    model: str | None = None,
    timeout_seconds: int | None = None,
    success_criteria: list[dict[str, str]] | None = None,
    cwd: str | None = None,
    outputs: list[str] | None = None,
    parent_id: str | None = None,
    dynamic: bool | None = None,
):
    from agentflow import kimi

    slug = model or openrouter_model()
    env = openrouter_node_env(model=slug)
    env.update(
        kimi_io_env(
            task_id,
            outputs=outputs,
            model=slug,
            parent_id=parent_id,
            dynamic=dynamic,
        )
    )
    kwargs: dict[str, Any] = {
        "task_id": task_id,
        "prompt": prompt,
        "model": slug,
        "tools": "read_write",
        "provider": openrouter_provider(),
        "env": env,
        "executable": kimi_executable(),
        "extra_args": kimi_extra_args(slug),
        "timeout_seconds": timeout_seconds or PROFILE_TIMEOUT_SECONDS[scan_profile()],
        "retries": 0,
        "target": node_target(cwd=cwd),
    }
    if success_criteria:
        kwargs["success_criteria"] = success_criteria
    return kimi(**kwargs)


def _goal_skill(slug: str) -> str:
    try:
        return playbook_prompt(slug)
    except FileNotFoundError:
        return ""


def threat_model_prompt(slug: str) -> str:
    skill = _goal_skill(slug)
    skill_block = f"{skill}\n\n" if skill else ""
    return (
        f"{skill_block}"
        f"{goal_workspace_preamble(slug)}\n"
        "Outcome for this node: write **THREAT_MODEL.md** in the cloned-repo workspace.\n\n"
        "THREAT_MODEL.md must define, precisely:\n"
        "- The attacker (who they are, what they control, what they do not).\n"
        "- Entry points and trust boundaries.\n"
        "- What a valid security finding looks like.\n"
        "- What does NOT count (local-only preconditions, operator error, "
        "intended reject paths, out-of-scope components).\n\n"
        "If THREAT / THREAT_PIN is non-empty, incorporate that pin as a priority "
        "constraint. It is not a fourth profile and it does not replace the model.\n\n"
        "Define the outcome space only. Do not prescribe how later hunters should "
        "search, which tools to run, or which files to open first.\n"
        "Do not write goals/, findings/, or report.md in this node.\n"
    )


def goal_author_prompt(slug: str) -> str:
    return (
        f"{goal_workspace_preamble(slug)}\n"
        "Outcome for this node: from THREAT_MODEL.md, write N goal prompts under "
        "**goals/** as markdown files.\n\n"
        "Read GOAL_COUNT from the environment (default 6, maximum 6). The intended "
        "split is 5 attack-surface goals plus 1 fully open roam unless GOAL_COUNT "
        "is smaller.\n\n"
        "Each goal file is one precise success condition — an outcome, not a path. "
        "Spend tokens defining what done looks like and what does not count. Do not "
        "tell the hunter how to get there.\n\n"
        "Name files ``goals/01-*.md`` … ``goals/0N-*.md`` so hunter-k can pick "
        "``goals/0k-*.md``. Put the open-roam goal last when N>=2.\n"
        "Write **goals/MANIFEST.md** listing each file and its one-line outcome.\n\n"
        "Before finalizing, self-red-team every goal for lazy outs a future model "
        "might take (declare done after a directory listing, write a generic "
        "checklist, treat “no bugs found yet” as success, survey instead of hunt). "
        "Revise the criteria so those outs do not count.\n"
        "Do not invent findings. Do not write report.md.\n"
    )


def surface_split_prompt(slug: str) -> str:
    return (
        f"{goal_workspace_preamble(slug)}\n"
        "Outcome for this node: after reading the tree and THREAT_MODEL.md, assign "
        "the top attack surfaces and the open roam into the goal files (rewrite "
        "goals/ and goals/MANIFEST.md as needed).\n\n"
        "One outcome per goal file. Keep filenames ``goals/01-*.md`` … so hunter-k "
        "still maps to ``goals/0k-*.md``.\n"
        "Write persistence into each goal: “no bugs found yet” is not done.\n"
        "Do not add a known-issues or GitHub-issue/PR duplicate search step.\n"
        "Do not invent findings. Do not write report.md.\n"
    )


def hunter_prompt(slug: str, index: int) -> str:
    padded = f"{index:02d}"
    task_id = f"hunter-{index}"
    result = f"findings/{task_id}/RESULT.md"
    return (
        f"{goal_workspace_preamble(slug)}\n"
        f"You are **{task_id}**. Pick the goal file matching ``goals/{padded}-*.md`` "
        "if it exists.\n\n"
        f"If no matching goal file is present, no-op cleanly: write **{result}** "
        "stating that this hunter was unassigned (GOAL_COUNT smaller than this "
        "slot, or the file is missing) and stop. That is success.\n\n"
        "If the goal file exists, hunt that single outcome against THREAT_MODEL.md. "
        "One outcome only — do not take on other hunters' surfaces.\n"
        "Persistence: “no bugs found yet” is not done. Keep going until you have "
        "a concrete candidate or you have exhausted the assigned surface and can "
        "write evidence of what you actually read and tried.\n\n"
        "Write candidates under "
        f"**findings/{task_id}/** (one file per candidate, plus {result}). "
        "RESULT.md must record candidates found or a clean miss with evidence.\n\n"
        "Do not search local known-findings files or open GitHub issues/PRs for "
        "duplicates. Do not invent. Do not write report.md.\n"
    )


def judge_a_prompt(slug: str) -> str:
    return (
        f"{goal_workspace_preamble(slug)}\n"
        "Outcome for this node: security-relevance judge versus THREAT_MODEL.md.\n\n"
        "Read every hunter RESULT.md and candidate under findings/hunter-*/. "
        "Keep only candidates that pose a genuine security risk inside the threat "
        "model. Drop impact-free nits, speculative style notes, and anything the "
        "threat model says does not count.\n\n"
        "Copy or rewrite survivors under **findings/validated-a/** "
        "(one file per survivor) and write **findings/validated-a/MANIFEST.md** "
        "listing keep/drop with a one-line reason. If nothing survives, the "
        "manifest must say so and record what you reviewed.\n"
        "Do not invent findings. Do not write report.md.\n"
    )


def judge_b_prompt(slug: str) -> str:
    return (
        f"{goal_workspace_preamble(slug)}\n"
        "Outcome for this node: PoC / exploitability judge. You are a different "
        "OpenRouter model than judge-a on purpose.\n\n"
        "Read findings/validated-a/ only (do not restore judge-a drops). "
        "A survivor must have a plausible attacker path and a minimal proof "
        "sketch — or a concrete reason the primitive is exploitable — under "
        "THREAT_MODEL.md.\n\n"
        "Copy or rewrite survivors under **findings/validated-b/** and write "
        "**findings/validated-b/MANIFEST.md** with keep/drop reasons. "
        "If nothing survives, say so with evidence of what you checked.\n"
        "Do not invent findings. Do not write report.md.\n"
    )


def assemble_prompt(slug: str) -> str:
    skill = _goal_skill(slug)
    skill_block = f"{skill}\n\n" if skill else ""
    dest = artifact_uri()
    return (
        f"{skill_block}"
        f"{goal_workspace_preamble(slug)}\n"
        "Outcome for this node: write the real **report.md** from dual-pass "
        "survivors only (findings/validated-b/).\n\n"
        "Also copy report.md to "
        f"{outputs_dir()}/{REPORT_NAME} if that directory exists.\n"
        f"The control plane uploads it to `{dest}`.\n\n"
        "Rules:\n"
        "- Include only judge-b survivors. Never invent a finding.\n"
        "- Empty findings are allowed if the report shows evidence of what was "
        "tried (threat model, goals, hunters, both judges).\n"
        "- No stub, placeholder, lorem ipsum, or “report coming soon” text.\n"
        "- Follow the playbook skill body for output shape.\n"
        "- Hunt only: no bounty-submit or disclosure-program language.\n"
    )


def build_goal_scan_graph(slug: str, *, description: str):
    """prepare → threat-model → goal-author → surface-split → hunters → judges → assemble → publish.

    Hunters are first-class dynamic nodes ``hunter-1``…``hunter-N`` from
    ``GOAL_COUNT`` (default 6, max 6). Each picks ``goals/0N-*.md`` if present
    and no-ops cleanly if missing. Known-issues / GitHub dedupe is omitted.
    """
    from agentflow import Graph, shell

    timeout = PROFILE_TIMEOUT_SECONDS[scan_profile()]
    cwd = repo_dir() if agentflow_target_mode() == "local" else None
    judge_a = judge_a_model()
    judge_b = judge_b_model()
    hunters_n = goal_count()

    with Graph(
        slug,
        description=description,
        working_dir=".",
        concurrency=max(hunters_n, 1),
        fail_fast=True,
    ) as graph:
        prepare = shell(
            task_id="prepare",
            script=wrap_shell_script("prepare", prepare_script(slug), outputs=[]),
            env=shell_io_env("prepare"),
            timeout_seconds=10 * 60,
            target=node_target(),
        )
        threat = _kimi_scan_node(
            task_id="threat-model",
            prompt=threat_model_prompt(slug),
            timeout_seconds=timeout,
            success_criteria=_file_criteria(THREAT_MODEL_NAME),
            cwd=cwd,
            outputs=[THREAT_MODEL_NAME],
        )
        author = _kimi_scan_node(
            task_id="goal-author",
            prompt=goal_author_prompt(slug),
            timeout_seconds=timeout,
            success_criteria=_file_criteria(GOALS_MANIFEST),
            cwd=cwd,
            outputs=[GOALS_MANIFEST],
        )
        split = _kimi_scan_node(
            task_id="surface-split",
            prompt=surface_split_prompt(slug),
            timeout_seconds=timeout,
            success_criteria=_file_criteria(GOALS_MANIFEST),
            cwd=cwd,
            outputs=[GOALS_MANIFEST],
        )
        hunters = [
            _kimi_scan_node(
                task_id=f"hunter-{index}",
                prompt=hunter_prompt(slug, index),
                timeout_seconds=timeout,
                success_criteria=_file_criteria(f"findings/hunter-{index}/RESULT.md"),
                cwd=cwd,
                outputs=[f"findings/hunter-{index}/RESULT.md"],
                parent_id="surface-split",
                dynamic=True,
            )
            for index in range(1, hunters_n + 1)
        ]
        relevance = _kimi_scan_node(
            task_id="judge-a",
            prompt=judge_a_prompt(slug),
            model=judge_a,
            timeout_seconds=timeout,
            success_criteria=_file_criteria(VALIDATED_A_MANIFEST),
            cwd=cwd,
            outputs=[VALIDATED_A_MANIFEST],
        )
        exploit = _kimi_scan_node(
            task_id="judge-b",
            prompt=judge_b_prompt(slug),
            model=judge_b,
            timeout_seconds=timeout,
            success_criteria=_file_criteria(VALIDATED_B_MANIFEST),
            cwd=cwd,
            outputs=[VALIDATED_B_MANIFEST],
        )
        assemble = _kimi_scan_node(
            task_id="assemble",
            prompt=assemble_prompt(slug),
            timeout_seconds=timeout,
            success_criteria=_file_criteria(REPORT_NAME),
            cwd=cwd,
            outputs=[REPORT_NAME],
        )
        publish = shell(
            task_id="publish",
            script=wrap_shell_script("publish", PUBLISH_SCRIPT.strip(), outputs=[]),
            env=shell_io_env("publish"),
            timeout_seconds=5 * 60,
            target=node_target(cwd=cwd),
            success_criteria=[
                {"kind": "output_contains", "value": "uploaded s3://"},
            ],
        )
        prepare >> threat >> author >> split
        split >> hunters
        hunters >> relevance >> exploit >> assemble >> publish
    return graph


def emit_goal(slug: str, *, description: str) -> None:
    graph = build_goal_scan_graph(slug, description=description)
    # No disk/S3 during validate; bootstrap is a no-op unless a run is live.
    bootstrap_run_io(graph.to_payload())
    print(graph.to_json())


PUBLISH_SCRIPT = r"""
set -euo pipefail
WORKDIR="${WORKDIR:-/workspace}"
OUTPUTS_DIR="${OUTPUTS_DIR:-/outputs}"
REPO_DIR="${WORKDIR}/repo"
ARTIFACTS_BUCKET="${ARTIFACTS_BUCKET:-midkernel-dev-artifacts}"
ARTIFACTS_PREFIX="${ARTIFACTS_PREFIX:-runs/}"
ARTIFACTS_PREFIX="${ARTIFACTS_PREFIX%/}/"
AWS_REGION="${AWS_REGION:-us-east-1}"
: "${RUN_ID:?RUN_ID is required}"
KEY="${ARTIFACTS_KEY:-${ARTIFACTS_PREFIX}${RUN_ID}/report.md}"

REPORT=""
for candidate in \
  "${OUTPUTS_DIR}/report.md" \
  "${REPO_DIR}/report.md" \
  "${WORKDIR}/report.md" \
  "./report.md"
do
  if [ -s "$candidate" ]; then
    REPORT="$candidate"
    break
  fi
done

if [ -z "$REPORT" ]; then
  echo "report.md is missing or empty; refusing to upload a stub" >&2
  exit 1
fi

python3 - "$REPORT" "$ARTIFACTS_BUCKET" "$KEY" "$AWS_REGION" <<'PY'
import pathlib, sys

path = pathlib.Path(sys.argv[1])
bucket, key, region = sys.argv[2], sys.argv[3], sys.argv[4]
text = path.read_text(encoding="utf-8", errors="replace")
lower = text.lower()
if len(text.strip()) < 80:
    raise SystemExit("report.md is too short to be a real review")
forbidden = (
    "lorem ipsum",
    "todo: write",
    "placeholder report",
    "stub report",
    "report coming soon",
    "not a real review",
)
if any(token in lower for token in forbidden):
    raise SystemExit("report.md looks like a stub; refusing upload")

try:
    import boto3
except ImportError as exc:
    raise SystemExit(f"boto3 is required to upload report.md: {exc}") from exc

boto3.client("s3", region_name=region).put_object(
    Bucket=bucket,
    Key=key,
    Body=text.encode("utf-8"),
    ContentType="text/markdown; charset=utf-8",
)
print(f"uploaded s3://{bucket}/{key} ({len(text.encode('utf-8'))} bytes)")
PY
"""
