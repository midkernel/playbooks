# midkernel/playbooks

MIT-licensed public playbooks: Midkernel default runs and third-party agent units users can customize.

Execution is **native [agentenv/agentflow](https://github.com/agentenv/agentflow)** (Python Graph API) with the **Kimi CLI harness via OpenRouter** (not Bedrock, not AI Gateway). OpenCode is **not required** — it was only an example. Do not build or block on an OpenCode adapter. The hard lock is **OpenRouter** for models.

Private Midkernel-only skills live in the private `skills` repo.

## Layout (app + MCP contract)

| Path | Who reads it |
| --- | --- |
| `<slug>.md` at repo root | Humans, MCP `list_playbooks`, app registry listing |
| `pipelines/<slug>.py` | Execution. `agentflow run` / `agentflow validate` |
| `pipelines/_midkernel.py` | Shared ECS target, env aliases, OpenRouter/Kimi + S3 helpers. Not a playbook |

Root markdown keeps `list_playbooks` working. The Midkernel Scan plugin walks **root** `.md` / `.yml` / `.yaml` / `.json` and optional `playbooks/`, `workflows/`, or `registry/` directories. It does **not** walk `pipelines/`, so graph files do not pollute the listing. `README.md` and `LICENSE` are ignored.

YAML frontmatter on each `<slug>.md`:

| Field | Purpose |
| --- | --- |
| `name`, `slug`, `description`, `surface` | Listing |
| `kind` | `agentflow-graph` (execution is the Python graph) |
| `pipeline` | Path the app/runner must start: `pipelines/<slug>.py` |
| `harness` | `kimi` |
| `provider` | `openrouter` |
| `target_repo`, `target_ref` | Optional default clone (`owner/name` + git ref) when `GITHUB_OWNER` / `GITHUB_NAME` / `GITHUB_REF` are unset |

The markdown **body** (after frontmatter) is the skill prompt. The graph loads it at build time. App `list_playbooks` / `GET /api/playbooks` should keep pointing at `<slug>.md` on `main`. Do not change the default slug `security-review` or path `security-review.md`.

## How Midkernel app starts a graph

1. User starts a Scan (`POST /api/scans/start` / MCP `start_run`) with `owner`, `name`, optional `playbook` (default `security-review`), `profile` (`low` \| `balanced` \| `max`), optional `threat` pin.
2. App creates a Run (`RUN_ID` = run id), burns credits, and submits **one** ECS Fargate Spot `RunTask` on **existing** midkernel-dev infra (see target below). Do **not** call agentflow zero-config (`{"kind":"ecs","region":"us-east-1"}`) — that invents a default-VPC SG named `agentflow` with SSH `0.0.0.0/0`.
3. The agent image (`midkernel-agentflow-agents`) fetches this repo and runs:

   ```bash
   MIDKERNEL_AGENTFLOW_TARGET=local agentflow run pipelines/${PLAYBOOK}.py
   ```

   `MIDKERNEL_AGENTFLOW_TARGET=local` keeps nodes **inside the already-launched task** (same filesystem, midkernel-dev task role, log group `/agentflow`). That avoids nested `RunTask` and stock agentflow creating IAM role `agentflow-ecs-execution` plus log group `/agentflow/<node.id>`.

4. The graph then runs inside that task. Default playbooks (`security-review`, Solana, Firedancer) are **prepare** → **review** → **publish**. `goal-security-review` is **prepare** → **threat-model** → **goal-author** → **surface-split** → **hunter-1..N** (`GOAL_COUNT`, default 6) → **judge-a** → **judge-b** → **assemble** → **publish**. Missing, empty, or stub `report.md` fails publish; the final report key is not written.

`externalAgentflowId` on the Run stays the Fargate task ARN. Observe completion the same way as today (`GET /api/runs/:id` + cron). Presign `s3://midkernel-dev-artifacts/runs/<RUN_ID>/report.md`. The Run UI also reads `graph.json` and per-node prompt/output/meta (see [Live graph artifacts](#live-graph-artifacts-run-ui)).

### Optional later: agentflow as the ECS control plane

If the app (or a long-running worker) runs `agentflow run pipelines/security-review.py` **without** `MIDKERNEL_AGENTFLOW_TARGET=local`, the published graph uses `kind: ecs` with the Midkernel IDs below. Stock agentflow still auto-creates `agentflow-ecs-execution` and `/agentflow/<node.id>` and does not set `taskRoleArn`. Sibling app/runner work must wrap `RegisterTaskDefinition` to use the midkernel-dev execution/task roles and log group `/agentflow` before that path is E2E.

## ECS target (existing infra)

From `pipelines/_midkernel.py` / app `AGENTFLOW_DEV_DEFAULTS`:

| Field | Value |
| --- | --- |
| region | `us-east-1` |
| cluster | `midkernel-dev` |
| subnets | `subnet-0f93686b81d5d8d7d`, `subnet-08ae98ea51ce9ccd7` |
| security group | `sg-015a103caabc861d0` |
| assign_public_ip | `true` |
| image | `489470371031.dkr.ecr.us-east-1.amazonaws.com/midkernel-agentflow-agents:latest` |
| execution role | `arn:aws:iam::489470371031:role/midkernel-dev-ecsTaskExecutionRole` |
| task role | `arn:aws:iam::489470371031:role/midkernel-dev-ecsTaskRole` |
| logs | `/agentflow` |
| artifacts | `s3://midkernel-dev-artifacts/runs/<RUN_ID>/report.md` plus live `graph.json` / `nodes/<id>/` |

`ECSTarget` in agentflow (pinned runner ref `09df0175ff2c88528c99b9f2c22f25b5e7622a8e`) accepts cluster, image, subnets, security groups, `assign_public_ip`, cpu/memory. It does **not** accept execution/task role ARNs or log group — those stay on the app-registered task definition.

Profile sizes (same as runner docs): `low` 1 vCPU / 2 GiB, `balanced` 2 / 4, `max` 4 / 8. Timeouts 15 / 30 / 60 minutes.

## Environment contract

Coordinate names with `midkernel/app` (`src/lib/agentflow-contract.ts`) and `midkernel/runner`. The graph accepts **both** spellings until those repos converge. Prefer the app names on `RunTask`.

| App (`AGENT_ENV`) | Runner alias | Required | Notes |
| --- | --- | --- | --- |
| `RUN_ID` | `RUN_ID` | yes | Artifact key segment. `[A-Za-z0-9._:-]{1,128}` |
| `GITHUB_OWNER` | same | playbook | Target owner. Required unless the playbook sets `target_repo` |
| `GITHUB_NAME` | same | playbook | Target name. Required unless the playbook sets `target_repo` |
| `PLAYBOOK` | `PLAYBOOK_SLUG` | no | Default `security-review` |
| `PROFILE` | `SCAN_PROFILE` | no | `low` \| `balanced` \| `max` |
| `THREAT` | `THREAT_PIN` | no | Optional pin, max 80 chars. Not a fourth profile. `goal-security-review` folds it into `THREAT_MODEL.md` |
| `GOAL_COUNT` | same | no | `goal-security-review` only. How many goal files to author **and** how many `hunter-*` nodes to emit. Default **6** (5 surfaces + 1 open roam). Max 6 |
| `JUDGE_A_MODEL` | same | no | OpenRouter slug for the relevance judge. Default `OPENROUTER_MODEL` / `moonshotai/kimi-k3` |
| `JUDGE_B_MODEL` | same | no | OpenRouter slug for the PoC/exploitability judge. Default `anthropic/claude-sonnet-4.5` (falls back to `openai/gpt-4o` if that would match judge-a) |
| `ARTIFACTS_BUCKET` | same | no | Default `midkernel-dev-artifacts` |
| `ARTIFACTS_PREFIX` | same | no | Default `runs/` |
| `ARTIFACTS_KEY` | same | no | Default `runs/<RUN_ID>/report.md` |
| `MODEL` / `OPENROUTER_MODEL` | `OPENROUTER_MODEL` | no | OpenRouter slug, default `moonshotai/kimi-k3` (optional `openrouter/` prefix) |
| `GITHUB_REF` | same | no | Shallow clone `--branch`. Playbooks with `target_ref` default that ref |
| `GITHUB_TOKEN` | same | yes* | Installation token; else SM `midkernel/dev/harness/github-token` |
| `OPENROUTER_API_KEY` | same | yes* | Else SM `midkernel/dev/harness/openrouter-api-key` |
| `MIDKERNEL_AGENTFLOW_TARGET` | same | no | `ecs` (default published graph) or `local` (in-task) |
| `MIDKERNEL_LOCAL` | same | no | `1` = laptop; use env keys, skip SM |

\*Required at runtime. Fail closed if missing.

Also export for Kimi OpenRouter (`openai_legacy`):

```bash
export OPENAI_API_KEY="$OPENROUTER_API_KEY"
export KIMI_API_KEY="$OPENROUTER_API_KEY"
export OPENAI_BASE_URL="https://openrouter.ai/api/v1"
```

Harness secrets are never in git. Image/task role may `GetSecretValue` on the two SM names above and `PutObject` on the artifacts prefix (`runs/<RUN_ID>/` including `graph.json` and `nodes/<id>/`).

## Live graph artifacts (Run UI)

Each agentflow node uploads its own I/O so the app can render a ReactFlow graph (status colors, prompt/output, progress %, ETA). Helpers live in `pipelines/_node_io.py` (wired from `_midkernel.py`) so `security-review` and `goal-security-review` share the same layout. Names stay aligned with app `src/lib/agentflow-contract.ts` (`RUN_ID`, `ARTIFACTS_BUCKET`, `ARTIFACTS_PREFIX`, `ARTIFACTS_KEY`).

```
s3://midkernel-dev-artifacts/runs/<RUN_ID>/report.md                 # final assemble (unchanged; stub-refusing)
s3://midkernel-dev-artifacts/runs/<RUN_ID>/graph.json                # topology + status + progress + ETA
s3://midkernel-dev-artifacts/runs/<RUN_ID>/nodes/<nodeId>/prompt.md
s3://midkernel-dev-artifacts/runs/<RUN_ID>/nodes/<nodeId>/output.md
s3://midkernel-dev-artifacts/runs/<RUN_ID>/nodes/<nodeId>/meta.json
```

`graph.json` nodes: `{ id, label, kind, status, startedAt?, finishedAt?, parentId?, dynamic?, artifacts }`. Edges: `{ id, source, target }`. Progress: `{ completed, total, percent, etaSeconds }` — ETA is `elapsed / completed * remaining` once at least one node has completed; otherwise `null`.

Production runs are **in-task** (`MIDKERNEL_AGENTFLOW_TARGET=local`, shared disk). Graph emit writes the helper to `$WORKDIR/.midkernel/node_io.py`, seeds `graph.json`, and uploads each node's prompt. Shell nodes wrap start/finish around their script (including failure + partial output). Kimi nodes set `executable` to that helper so the same process uploads prompt at start and output + meta on success or failure. Dynamic hunters (`hunter-1`…`N` from `GOAL_COUNT`) are first-class: present in `graph.json` with edges `surface-split → hunter-N → judge-a`, and re-spawned (idempotent) when `surface-split` finishes.

Deviation vs a purely dynamic agentflow fan-out: agentflow still needs the hunter copies declared when the graph is emitted. `GOAL_COUNT` is read then (task env), so N is exact for that run. Hunters are marked `dynamic: true` for the UI. The published ECS-per-node path (`MIDKERNEL_AGENTFLOW_TARGET=ecs`) still embeds the helper in each shell script; Kimi I/O there requires the helper file on the task disk (the in-task path is the one Midkernel actually launches).

## Playbooks

### security-review

Default Midkernel Scan graph. `pipelines/security-review.py`. Surface: `scan`. Caller must supply `GITHUB_OWNER` / `GITHUB_NAME`.

### solana-validator-security

Same graph shape; skill body is the Agave / jito-solana-class review. `pipelines/solana-validator-security.py`.

Default private hunt mirror: `midkernel/bounty-target-jito-solana` @ `master` (overridable). Hunt only — no Immunefi submit.

### firedancer-fuzz-triage

Same graph shape; skill body is FireBAM / Firedancer-class fuzz triage. `pipelines/firedancer-fuzz-triage.py`.

Default private hunt mirror: `midkernel/bounty-target-jito-firebam` @ `main` (overridable). Shallow clone, `--no-recurse-submodules` (Frankendancer `agave/` stays out unless the crash stack lands there). Hunt only — no Immunefi submit.

### goal-security-review

Trail of Bits–style `/goal` hunt (outcome, not path). `pipelines/goal-security-review.py`. Same OpenRouter + Kimi lock, Midkernel-dev ECS target, and fail-closed `report.md` → `s3://midkernel-dev-artifacts/runs/<RUN_ID>/report.md` as `security-review`. Caller supplies `GITHUB_OWNER` / `GITHUB_NAME` (no default target).

Graph (shared-workspace file handoff under the cloned repo):

1. **prepare** — clone, OpenRouter/Kimi config, secrets (same `prepare_script` as the other Scan playbooks).
2. **threat-model** — write `THREAT_MODEL.md` (attacker, entry points, trust boundaries, what does **not** count). Honors `THREAT` / `THREAT_PIN`. Does not prescribe how to hunt.
3. **goal-author** — from the threat model, write N goal prompts under `goals/` (`01-*.md` …). Each file is one precise success condition. Self-red-teams lazy outs. `GOAL_COUNT` default **6** (5 surfaces + 1 open roam).
4. **surface-split** — read the tree + threat model; assign surfaces / open roam into those goal files. Persistence: “no bugs found yet” is not done.
5. **hunter-1** … **hunter-N** — first-class dynamic nodes from `GOAL_COUNT` (default 6). Each picks `goals/0N-*.md` if present and no-ops cleanly if missing. Candidates go under `findings/hunter-N/`. **No** known-issues / GitHub issue-or-PR duplicate search. `graph.json` records `surface-split → hunter-N → judge-a`.
6. **judge-a** — security-relevance vs `THREAT_MODEL.md` (default Kimi / `OPENROUTER_MODEL`). Survivors → `findings/validated-a/`.
7. **judge-b** — PoC / exploitability on a **different** OpenRouter model (default `anthropic/claude-sonnet-4.5`). Survivors → `findings/validated-b/`.
8. **assemble** — only dual-pass survivors → `report.md`. Empty findings with evidence of what was tried is allowed. Never invent. No stub language.
9. **publish** — same `PUBLISH_SCRIPT` (nonempty, non-stub `report.md` or fail closed).

Out of scope: known-issues / issue-tracker dedupe, CVE / P-critical variant orchestration, aicov-style coverage tooling.

## Validate locally

```bash
python3 -m pip install "agentflow @ git+https://github.com/agentenv/agentflow.git@09df0175ff2c88528c99b9f2c22f25b5e7622a8e"
python3 pipelines/security-review.py | python3 -m json.tool
python3 pipelines/solana-validator-security.py | python3 -m json.tool
python3 pipelines/firedancer-fuzz-triage.py | python3 -m json.tool
python3 pipelines/goal-security-review.py | python3 -m json.tool
MIDKERNEL_AGENTFLOW_TARGET=local python3 pipelines/security-review.py | python3 -m json.tool
python3 -m pytest -q
```

`agentflow validate pipelines/<slug>.py` if the CLI is on `PATH`. Do not run a live graph without a real OpenRouter key and a target repo — CI only validates schema.

MIT.
