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


def openrouter_model() -> str:
    raw = env_first("OPENROUTER_MODEL", "MODEL", default=DEFAULT_OPENROUTER_MODEL)
    if raw.startswith("openrouter/"):
        raw = raw[len("openrouter/") :]
    if "/" not in raw:
        return DEFAULT_OPENROUTER_MODEL
    return raw


def artifact_key(run_id: str | None = None) -> str:
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


def openrouter_node_env() -> dict[str, str]:
    key = env_first("OPENROUTER_API_KEY", "OPENAI_API_KEY")
    env = {
        "OPENAI_BASE_URL": OPENROUTER_BASE_URL,
    }
    if key:
        env["OPENROUTER_API_KEY"] = key
        env["OPENAI_API_KEY"] = key
        env["KIMI_API_KEY"] = key
    return env


def kimi_openrouter_config(model: str | None = None) -> str:
    slug = model or openrouter_model()
    return "\n".join(
        [
            "default_model = \"midkernel\"",
            "default_thinking = false",
            "default_yolo = true",
            "",
            "[providers.openrouter]",
            "type = \"openai_legacy\"",
            f"base_url = \"{OPENROUTER_BASE_URL}\"",
            "api_key = \"OVERRIDE_VIA_ENV\"",
            "",
            "[models.midkernel]",
            "provider = \"openrouter\"",
            f"model = \"{slug}\"",
            "max_context_size = 262144",
            "",
        ]
    )


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

mkdir -p "$WORKDIR" "$OUTPUTS_DIR" "$HOME/.kimi"

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
if not os.environ.get("OPENROUTER_API_KEY", "").strip() and os.environ.get("MIDKERNEL_LOCAL") != "1":
    value = load_secret(secret_id, region)
    if value:
        print(value, file=open(os.environ["HOME"] + "/.midkernel-openrouter", "w"))
if not os.environ.get("GITHUB_TOKEN", "").strip() and os.environ.get("MIDKERNEL_LOCAL") != "1":
    value = load_secret(gh_secret_id, region)
    if value:
        print(value, file=open(os.environ["HOME"] + "/.midkernel-github", "w"))
PY

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

cat > "$HOME/.kimi/config.toml" <<EOF
default_model = "midkernel"
default_thinking = false
default_yolo = true

[providers.openrouter]
type = "openai_legacy"
base_url = "https://openrouter.ai/api/v1"
api_key = "OVERRIDE_VIA_ENV"

[models.midkernel]
provider = "openrouter"
model = "${OPENROUTER_MODEL}"
max_context_size = 262144
EOF

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
            script=prepare_script(slug),
            timeout_seconds=10 * 60,
            target=node_target(),
        )
        review = kimi(
            task_id="review",
            prompt=prompt,
            model=model,
            tools="read_write",
            provider=openrouter_provider(),
            env=openrouter_node_env(),
            extra_args=["--config", kimi_openrouter_config(model)],
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
            script=PUBLISH_SCRIPT.strip(),
            timeout_seconds=5 * 60,
            target=node_target(cwd=review_cwd),
            success_criteria=[
                {"kind": "output_contains", "value": "uploaded s3://"},
            ],
        )
        prepare >> review >> publish
    return graph


def emit(slug: str, *, description: str) -> None:
    print(build_scan_graph(slug, description=description).to_json())


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
