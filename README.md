# midkernel/playbooks

MIT-licensed public playbooks: Midkernel default runs and third-party agent units users can customize.

Not every entry is a full workflow — thin skill packs belong here too.

Private Midkernel-only skills live in the private `skills` repo.

## Layout

Each playbook is a Markdown file at the **repository root** named `<slug>.md` (for example `security-review.md`).

YAML frontmatter holds `name`, `slug`, `description`, and `surface`. The body is the run prompt only.

The Midkernel Scan MCP/plugin lists playbooks from this public registry via `list_playbooks`.

## security-review

This is the default Midkernel Scan playbook. Single skill, one-shot — not a multi-step agentflow graph. Surface: `scan`.

## solana-validator-security

Focused Scan playbook for Agave / jito-solana-class validator clients (banking stage, runtime, SVM, accounts DB, net, consensus, Jito/BAM overlay if present). Single skill, one-shot. Surface: `scan`.

## firedancer-fuzz-triage

FireBAM / Firedancer-class sanitizer and fuzz-crash triage (repro, minimize, invalid-input vs real bug, patch-oriented). Single skill, one-shot. Surface: `scan`.
