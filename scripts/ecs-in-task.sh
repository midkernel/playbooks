#!/usr/bin/env bash
# In-task entry: run pipelines/${PLAYBOOK}.py locally so _node_io uploads
# graph.json + nodes/* (and publish still writes report.md).
#
# The current agent image CMD is midkernel-runner (single kimi + <slug>.md).
# That path never imports playbooks, which is why dogfood
# cmtu8jtu00003l1043oi0at41 only has report.md on S3.
#
# Usage (existing image — git + agentflow already on PATH):
#   export WORKDIR=/workspace MIDKERNEL_NODE_IO=1 MIDKERNEL_AGENTFLOW_TARGET=local
#   export MIDKERNEL_KIMI_BIN=/opt/midkernel/kimi.bin
#   export RUN_ID=... PLAYBOOK=goal-security-review
#   scripts/ecs-in-task.sh
#   # or: curl -fsSL https://raw.githubusercontent.com/midkernel/playbooks/main/scripts/ecs-in-task.sh | bash
#
# Clones midkernel/playbooks when this checkout is missing (curl | bash).
set -euo pipefail

export WORKDIR="${WORKDIR:-/workspace}"
export OUTPUTS_DIR="${OUTPUTS_DIR:-/outputs}"
export MIDKERNEL_NODE_IO="${MIDKERNEL_NODE_IO:-1}"
export MIDKERNEL_AGENTFLOW_TARGET="${MIDKERNEL_AGENTFLOW_TARGET:-local}"
if [ -x /opt/midkernel/kimi.bin ]; then
  export MIDKERNEL_KIMI_BIN="${MIDKERNEL_KIMI_BIN:-/opt/midkernel/kimi.bin}"
fi

mkdir -p "$WORKDIR" "$OUTPUTS_DIR" "$WORKDIR/.midkernel"
echo "node io: ecs-in-task WORKDIR=$WORKDIR RUN_ID=${RUN_ID:-unset} PLAYBOOK=${PLAYBOOK:-${PLAYBOOK_SLUG:-unset}} MIDKERNEL_NODE_IO=$MIDKERNEL_NODE_IO MIDKERNEL_AGENTFLOW_TARGET=$MIDKERNEL_AGENTFLOW_TARGET" >&2

PLAYBOOK="${PLAYBOOK:-${PLAYBOOK_SLUG:-goal-security-review}}"
PLAYBOOKS_OWNER="${PLAYBOOKS_OWNER:-midkernel}"
PLAYBOOKS_NAME="${PLAYBOOKS_NAME:-playbooks}"
PLAYBOOKS_REF="${PLAYBOOKS_REF:-main}"

ROOT=""
if [ -n "${BASH_SOURCE[0]:-}" ] && [ -f "${BASH_SOURCE[0]}" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  CANDIDATE="$(cd "$SCRIPT_DIR/.." && pwd)"
  if [ -f "$CANDIDATE/pipelines/${PLAYBOOK}.py" ]; then
    ROOT="$CANDIDATE"
  fi
fi

if [ -z "$ROOT" ]; then
  ROOT="${MIDKERNEL_PLAYBOOKS_DIR:-$WORKDIR/.midkernel/playbooks}"
  if [ ! -f "$ROOT/pipelines/${PLAYBOOK}.py" ]; then
    echo "node io: cloning github.com/${PLAYBOOKS_OWNER}/${PLAYBOOKS_NAME}@${PLAYBOOKS_REF} → $ROOT" >&2
    rm -rf "$ROOT"
    git clone --depth 1 --branch "$PLAYBOOKS_REF" \
      "https://github.com/${PLAYBOOKS_OWNER}/${PLAYBOOKS_NAME}.git" "$ROOT"
  fi
fi

PIPELINE="$ROOT/pipelines/${PLAYBOOK}.py"
if [ ! -f "$PIPELINE" ]; then
  echo "node io: pipeline missing at $PIPELINE" >&2
  exit 2
fi

if ! command -v agentflow >/dev/null 2>&1; then
  echo "node io: agentflow is not on PATH" >&2
  exit 2
fi

echo "node io: agentflow run $PIPELINE" >&2
exec agentflow run "$PIPELINE"
