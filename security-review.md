---
name: security-review
slug: security-review
description: Default Midkernel Scan playbook. Native agentflow graph (Kimi CLI via OpenRouter on midkernel-dev ECS).
surface: scan
kind: agentflow-graph
pipeline: pipelines/security-review.py
harness: kimi
provider: openrouter
---

Perform a /security-review on this project.

Write the review to `report.md` (real findings only — no stubs). Midkernel uploads that file to `s3://midkernel-dev-artifacts/runs/<RUN_ID>/report.md`.
