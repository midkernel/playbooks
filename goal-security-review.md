---
name: goal-security-review
slug: goal-security-review
description: Trail of Bits–style /goal security hunt. Native agentflow graph (Kimi CLI via OpenRouter on midkernel-dev ECS). Threat model, authored goals, parallel hunter fan-out, dual-pass judges, report.md.
surface: scan
kind: agentflow-graph
pipeline: pipelines/goal-security-review.py
harness: kimi
provider: openrouter
---

Perform a Trail of Bits–style /goal security hunt on this project. One precise outcome per agent. Define the outcome, not the path.

Method (the graph runs these as separate nodes; do not collapse them):

1. Write `THREAT_MODEL.md` — attacker, entry points, trust boundaries, what does NOT count. If `THREAT` / `THREAT_PIN` is set, incorporate that pin. Do not prescribe how to hunt.
2. Author N goal prompts under `goals/` (`GOAL_COUNT`, default **6** = 5 surfaces + 1 open roam). Each goal is one success condition. Self-red-team lazy outs before finalizing.
3. After reading the tree, assign the top attack surfaces and the open roam into those goal files. One outcome per file. Persistence: “no bugs found yet” is not done.
4. Hunt each goal independently. Write candidates under `findings/`. Do not search local known-findings or open GitHub issues/PRs for duplicates.
5. Dual-pass judges: (A) security-relevance vs `THREAT_MODEL.md`; (B) a different OpenRouter model, PoC / exploitability. Only dual-pass survivors are findings.
6. Assemble **`report.md`** from those survivors. Empty findings with evidence of what was tried is allowed. Never invent. No stub language.

Out of scope for this playbook: known-issues / issue-tracker dedupe, CVE / P-critical variant orchestration, aicov-style coverage tooling.

Output shape for `report.md`:

- Ranked dual-pass survivors (severity, location, trigger, impact, residual risk, proof sketch).
- If none: a clean miss with the threat model, goals hunted, and evidence of what was read — not a placeholder.
- Hunt only. No bounty-submit, disclosure, or program-filing language.

Write the review to `report.md`. Midkernel uploads it to `s3://midkernel-dev-artifacts/runs/<RUN_ID>/report.md`.
