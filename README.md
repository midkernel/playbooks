# midkernel/playbooks

MIT-licensed public playbooks: Midkernel default runs and third-party agent units users can customize.

Execution is **native [agentenv/agentflow](https://github.com/agentenv/agentflow)** (Python Graph API). OpenCode one-shot is **deferred** — there is no OpenCode adapter in agentflow; Midkernel uses the **Kimi CLI harness via OpenRouter** (not Bedrock, not AI Gateway).

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

The markdown **body** (after frontmatter) is the skill prompt. The graph loads it at build time. App `list_playbooks` / `GET /api/playbooks` should keep pointing at `<slug>.md` on `main`. Do not change the default slug `security-review` or path `security-review.md`.

## How Midkernel app starts a graph

1. User starts a Scan (`POST /api/scans/start` / MCP `start_run`) with `owner`, `name`, optional `playbook` (default `security-review`), `profile` (`low` \| `balanced` \| `max`), optional `threat` pin.
2. App creates a Run (`RUN_ID` = run id), burns credits, and submits **one** ECS Fargate Spot `RunTask` on **existing** midkernel-dev infra (see target below). Do **not** call agentflow zero-config (`{"kind":"ecs","region":"us-east-1"}`) — that invents a default-VPC SG named `agentflow` with SSH `0.0.0.0/0`.
3. The agent image (`midkernel-agentflow-agents`) fetches this repo and runs:

   ```bash
   MIDKERNEL_AGENTFLOW_TARGET=local agentflow run pipelines/${PLAYBOOK}.py
   ```

   `MIDKERNEL_AGENTFLOW_TARGET=local` keeps nodes **inside the already-launched task** (same filesystem, midkernel-dev task role, log group `/agentflow`). That avoids nested `RunTask` and stock agentflow creating IAM role `agentflow-ecs-execution` plus log group `/agentflow/<node.id>`.

4. The graph: **prepare** (secrets + clone + Kimi OpenRouter config) → **review** (`kimi()` / OpenRouter) → **publish** (`report.md` to S3). Missing, empty, or stub reports fail the node; nothing is uploaded.

`externalAgentflowId` on the Run stays the Fargate task ARN. Observe completion the same way as today (`GET /api/runs/:id` + cron). Presign `s3://midkernel-dev-artifacts/runs/<RUN_ID>/report.md`.

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
| artifacts | `s3://midkernel-dev-artifacts/runs/<RUN_ID>/report.md` |

`ECSTarget` in agentflow (pinned runner ref `09df0175ff2c88528c99b9f2c22f25b5e7622a8e`) accepts cluster, image, subnets, security groups, `assign_public_ip`, cpu/memory. It does **not** accept execution/task role ARNs or log group — those stay on the app-registered task definition.

Profile sizes (same as runner docs): `low` 1 vCPU / 2 GiB, `balanced` 2 / 4, `max` 4 / 8. Timeouts 15 / 30 / 60 minutes.

## Environment contract

Coordinate names with `midkernel/app` (`src/lib/agentflow-contract.ts`) and `midkernel/runner`. The graph accepts **both** spellings until those repos converge. Prefer the app names on `RunTask`.

| App (`AGENT_ENV`) | Runner alias | Required | Notes |
| --- | --- | --- | --- |
| `RUN_ID` | `RUN_ID` | yes | Artifact key segment. `[A-Za-z0-9._:-]{1,128}` |
| `GITHUB_OWNER` | same | yes | Target repo owner |
| `GITHUB_NAME` | same | yes | Target repo name |
| `PLAYBOOK` | `PLAYBOOK_SLUG` | no | Default `security-review` |
| `PROFILE` | `SCAN_PROFILE` | no | `low` \| `balanced` \| `max` |
| `THREAT` | `THREAT_PIN` | no | Optional pin, max 80 chars. Not a fourth profile |
| `ARTIFACTS_BUCKET` | same | no | Default `midkernel-dev-artifacts` |
| `ARTIFACTS_PREFIX` | same | no | Default `runs/` |
| `ARTIFACTS_KEY` | same | no | Default `runs/<RUN_ID>/report.md` |
| `MODEL` / `OPENROUTER_MODEL` | `OPENROUTER_MODEL` | no | OpenRouter slug, default `moonshotai/kimi-k3` (optional `openrouter/` prefix) |
| `GITHUB_REF` | same | no | Shallow clone `--branch` |
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

Harness secrets are never in git. Image/task role may `GetSecretValue` on the two SM names above and `PutObject` on the artifacts prefix.

## Playbooks

### security-review

Default Midkernel Scan graph. `pipelines/security-review.py`. Surface: `scan`.

### solana-validator-security

Same graph shape; skill body is the Agave / jito-solana-class review. `pipelines/solana-validator-security.py`.

### firedancer-fuzz-triage

Same graph shape; skill body is FireBAM / Firedancer-class fuzz triage. `pipelines/firedancer-fuzz-triage.py`.

## Validate locally

```bash
python3 -m pip install "agentflow @ git+https://github.com/agentenv/agentflow.git@09df0175ff2c88528c99b9f2c22f25b5e7622a8e"
python3 pipelines/security-review.py | python3 -m json.tool
MIDKERNEL_AGENTFLOW_TARGET=local python3 pipelines/security-review.py | python3 -m json.tool
python3 -m pytest -q
```

`agentflow validate pipelines/security-review.py` if the CLI is on `PATH`. Do not run a live graph without a real OpenRouter key and a target repo — CI only validates schema.

MIT.
