#!/usr/bin/env bash
# In-task entry for midkernel/runner (follow-up on that repo).
#
# App RunTask today has no command override, so the image runs
# ``midkernel-runner`` (single kimi + report.md). That never imports
# pipelines/_node_io.py, so graph.json is never written.
#
# Runner should exec this script (or the equivalent env + agentflow run)
# when pipelines/${PLAYBOOK}.py exists:
#
#   export MIDKERNEL_AGENTFLOW_TARGET=local
#   export MIDKERNEL_NODE_IO=1
#   export WORKDIR=/workspace          # image default; shared disk
#   export MIDKERNEL_KIMI_BIN=/opt/midkernel/kimi.bin
#   scripts/ecs-in-task.sh
#
# Do not use PATH ``kimi`` (runner wrapper requires report.md after every node).
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

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PLAYBOOK="${PLAYBOOK:-${PLAYBOOK_SLUG:-goal-security-review}}"
PIPELINE="$ROOT/pipelines/${PLAYBOOK}.py"
if [ ! -f "$PIPELINE" ]; then
  echo "node io: pipeline missing at $PIPELINE" >&2
  exit 2
fi

if ! command -v agentflow >/dev/null 2>&1; then
  echo "node io: agentflow is not on PATH" >&2
  exit 2
fi

exec agentflow run "$PIPELINE"
