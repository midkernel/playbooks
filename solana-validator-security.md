---
name: solana-validator-security
slug: solana-validator-security
description: Outcome-first Scan playbook for Agave / jito-solana-class validator clients. Native agentflow graph (Kimi CLI via OpenRouter).
surface: scan
kind: agentflow-graph
pipeline: pipelines/solana-validator-security.py
harness: kimi
provider: openrouter
---

Review this Agave / jito-solana-class validator client for security defects that can take a node down, corrupt ledger or account state, or let untrusted network or transaction input influence consensus, execution, or persisted state. Rust-first. Report concrete findings with file paths, preconditions, and impact on a running validator. Do not write a generic whole-repo survey.

Prioritize, in order:

1. Banking stage and transaction scheduling — ingest, forwarding, cost/lock accounting, bundle or atomic-batch paths if present.
2. Runtime and Bank / BankForks — slot state, forks, feature activation, rewards, sysvar and builtin transitions.
3. SVM / Sealevel — program load, CPI, syscalls, compute budget, account borrow/alias rules, precompiles.
4. Accounts DB and snapshots — AppendVec / index integrity, shrinking, hash, snapshot load/verify, stale or aliasing account views.
5. Networking — TPU/TVU, QUIC, sigverify, gossip, Turbine/shreds, repair, XDP if present.
6. Consensus — Tower BFT / Votor, votes, PoH, leader schedule, fork choice.
7. Jito / BAM overlay only if this tree has it — `bundle`, `jito-*`, `bam_*`, tip-payment, block-engine or scheduler gRPC, shred-forward overrides. Treat those as first-class when present; do not invent them if absent.

Skip unless a finding clearly reaches validator safety:

- CLI, docs, faucet, watchtower, install, keygen, tokens, remote-wallet, program-test, benches, metrics exporters.
- RPC/JSON-RPC and Geyser unless they can crash the process, leak validator keys, or mutate bank/consensus state.
- Unrelated workspace crates that are obviously client SDK, tooling, or test-only (confirm via each crate's `[package].name`; do not infer from directory names).
- Operator runbooks, release process, and coverage scripts.

Method: map the TPU/TVU and runtime entrypoints, then read the hot paths above. Prefer defects reachable from the network, untrusted transactions, snapshots, or gossip over local-only logic errors. If the tree is a Jito or BAM fork, diff mentally against stock Agave and spend extra time on the overlay.

Output only: ranked findings (severity, location, trigger, impact, residual risk) and a short "looked, clean" list for the priority areas you covered. No bounty-submit, disclosure, or program-filing language.

Write the review to `report.md`. Midkernel uploads it to `s3://midkernel-dev-artifacts/runs/<RUN_ID>/report.md`.
