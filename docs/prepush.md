# Contributor pre-push checks

`python3 scripts/setup-dev.py` prepares a regular local `.venv` using Python
>=3.11, installs this repository's existing `.[dev]` dependencies (including the
existing pinned agentflow revision), then runs the isolated hook installer.
An existing venv is reused, not replaced; incompatible/incomplete paths fail.
Setup may download dependencies and is an explicit contributor action. A failed
setup/installer is not successful enrollment. There is no package lifecycle
hook or CI step that installs Git hooks.

The shared default dispatcher and per-worktree enrollment marker are the same
reviewed implementation as [design#10](https://github.com/midkernel/design/pull/10).
The installer writes no Git identity/configuration, preserves custom hooks and
any effective `core.hooksPath`, and refuses conflicting/symlink files. Installing
here does not enroll a linked sibling. An enrolled older branch without support
files fails. To unenroll, remove only `midkernel-prepush-v1` beneath this
worktree's `git rev-parse --absolute-git-dir`; keep the shared dispatcher.

Only a single branch update at current HEAD is checked. Tags, batches, non-HEAD
tips and other namespaces are unsupported; single branch/tag deletions and empty
updates require no content check. Staged/unstaged/nonignored untracked changes,
index ignore flags and submodules block validation. Cleanliness and HEAD are
checked before and after; no stash/reset/commit is performed automatically.

The adapter requires `.venv/bin/python` and pytest, disables third-party pytest
plugin autoload, and runs the existing three inert `tests/test_registry.py`
contracts with no pytest cache. They check root listing metadata, pipeline file
presence and README contract text. They import no graphs/provider code and make
no network requests. This is **not** Python formatting, lint, typechecking, graph
semantic validation or the full test suite. No such formatter/linter/typechecker
is configured in the existing project. CI still runs all tests and all four
`agentflow validate` commands on every PR/main validation.

Validators receive a small environment, temporary HOME/cache and inherited PATH.
This is not an OS sandbox or hermetic validation: ignored venv/tool inputs and
source are trusted, ordinary Git stat checks and concurrent edits have limits,
and earlier commits in the push are not individually validated. `--no-verify`,
Git hook configuration or removed/edited hook files can bypass local checks.
CI remains authoritative. No live graph, agent/provider command, Docker, browser
or automatic install runs from the hook.

Generic boundary tests: `python3 -I scripts/prepush/test_hook.py` (synthetic local
Git fixtures only). Adoption evidence and hosted timing limits are in
[CI performance](ci-performance.md).
