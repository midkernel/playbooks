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
# Disable the image BASH_ENV hook (clones into /workspace + report.md EXIT trap).
export BASH_ENV=/dev/null
export MIDKERNEL_NODE_READY=1
if [ -x /opt/midkernel/kimi.bin ]; then
  export MIDKERNEL_KIMI_BIN="${MIDKERNEL_KIMI_BIN:-/opt/midkernel/kimi.bin}"
  export KIMI_REAL_BIN="${KIMI_REAL_BIN:-$MIDKERNEL_KIMI_BIN}"
fi

mkdir -p "$WORKDIR" "$OUTPUTS_DIR" "$WORKDIR/.midkernel/bin"
echo "node io: ecs-in-task WORKDIR=$WORKDIR RUN_ID=${RUN_ID:-unset} PLAYBOOK=${PLAYBOOK:-${PLAYBOOK_SLUG:-unset}} MIDKERNEL_NODE_IO=$MIDKERNEL_NODE_IO MIDKERNEL_AGENTFLOW_TARGET=$MIDKERNEL_AGENTFLOW_TARGET MIDKERNEL_KIMI_BIN=${MIDKERNEL_KIMI_BIN:-unset}" >&2

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

# Agentflow local preflight execs ``<executable> --version`` (not python3).
HELPER="$ROOT/pipelines/_node_io.py"
if [ -f "$HELPER" ]; then
  chmod 755 "$HELPER" || echo "node io: chmod +x $HELPER failed" >&2
fi

# PATH shim so any leftover ``kimi`` lookup hits kimi.bin, not the report.md wrapper.
SHIM="$WORKDIR/.midkernel/bin/kimi"
if [ -n "${MIDKERNEL_KIMI_BIN:-}" ]; then
  cat > "$SHIM" <<EOF
#!/bin/sh
REAL="\${MIDKERNEL_KIMI_BIN:-$MIDKERNEL_KIMI_BIN}"
if [ ! -x "\$REAL" ]; then
  echo "node io: MIDKERNEL_KIMI_BIN missing or not executable: \$REAL" >&2
  exit 127
fi
exec "\$REAL" "\$@"
EOF
  chmod 755 "$SHIM"
  export PATH="$WORKDIR/.midkernel/bin:$PATH"
fi

# --preflight never: AUTO preflight still probes every local kimi node with
# ``_node_io.py --version``. That must succeed (this helper forwards to
# kimi.bin) but skipping doctor avoids a second failure mode.
echo "node io: agentflow run --preflight never $PIPELINE" >&2
exec agentflow run --preflight never "$PIPELINE"
