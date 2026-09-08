---
name: FireBAM/Firedancer-class fuzz triage
slug: firedancer-fuzz-triage
description: Patch-oriented sanitizer and fuzz-crash triage for FireBAM / Firedancer-class C/C++ clients. Single skill, one-shot.
surface: scan
kind: single-skill
---

Triage sanitizer crashes and fuzz failures in this FireBAM / Firedancer-class C/C++ validator client into patch-ready bugs versus invalid-input or harness noise. Goal: a minimized repro, a root-cause note, and a concrete fix shape — not a generic security survey and not a bounty write-up.

Work the crash, not the whole tree:

1. Identify the harness, corpus entry, and sanitizer (ASan, UBSan, MSan, libFuzzer / AFL / honggfuzz). Rebuild with the matching extras (`EXTRAS="fuzz asan"`, `EXTRAS="fuzz ubsan"`, or the repo's equivalent). For UBSan, use `UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1` so reports abort with a usable stack.
2. Reproduce, then minimize (libFuzzer `-minimize_crash=1` or equivalent). Keep the smallest input that still hits the same stack / UB class.
3. Classify the failure:
   - Real bug: memory corruption, use-after-free, OOB, uninit read, reachable UB in production parse/execute/net paths, or a crash on input the node must reject gracefully.
   - Invalid input / expected reject: harness or production code already returns an error; the crash is only in a test assertion, a debug-only abort, or a fixture the corpus marks invalid.
   - Harness artifact: fuzzer stub, missing mock, or sanitizer noise that cannot occur on the validator tile path.
4. Prefer crashes in `src/` tiles and libraries (`disco` / BAM, `ballet`, `flamenco`, `tango`, `waltz`, pack/exec/poh/shred, QUIC, sbpf loader). Frankendancer `agave/` only if the stack actually lands there.

Skip unless the stack requires it:

- Operator docs, Grafana, containers, geoip, and release-tag scripts.
- Immunefi / bounty-program text; do not draft submissions.
- Unrelated workspace or sibling checkouts (`../bam`, `../jito-solana`) unless the crash is a wire-contract mismatch you can prove from this tree.
- Known-invalid ELF / corpus fixtures that the loader is specified to reject, unless rejection itself faults.

Patch-oriented output only:

- Crash class and sanitizer signature.
- Minimized repro (command + input path or hex).
- Root cause (what invariant broke; why invalid input should have been rejected earlier, or why valid-looking input is unsafe).
- Suggested fix location and shape (bounds check, reject path, lifetime, integer/shift, ownership). Do not land a speculative drive-by refactor.
- Residual risk and any nearby sibling sites.

If nothing reproduces or every crash is harness/invalid-input, say so in one short note and stop.
