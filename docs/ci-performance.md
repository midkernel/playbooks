# CI timing and dependency caching

Coordination: [mail #20](https://github.com/midkernel/mail/issues/20).
Baseline source: `8c5c186a9a312571c5d9021cf90995394aa60b62`.

| Successful first attempt | Workflow wall | Job | Setup | Checks | Dependency install |
| --- | ---: | ---: | ---: | ---: | ---: |
| [PR 41293271243](https://github.com/midkernel/playbooks/actions/runs/41293271243) | 42s | 39s | 16s | 20s | 14s |
| [Main 41300216695](https://github.com/midkernel/playbooks/actions/runs/41300216695) | 45s | 42s | 17s | 22s | 15s |

Observed on 2026-11-01. Workflow wall is creation to last job completion,
not a developer push timestamp. Job creation-to-start proxies were 2s and 3s;
they do not isolate machine waiting. Teardown/residual time is separate.

`setup-python@v5` now caches pip's download/wheel cache using `pyproject.toml`
as the dependency input, with the action's Python/platform separation.
It does not cache an installed environment. The editable install, unit tests
and all four graph validations still run unconditionally on PR and main.
The immutable agentflow revision remains unchanged. Ranged dependencies still
resolve normally; a cache hit is not a dependency lock or a passed validation.
See the [action's caching documentation](https://github.com/actions/setup-python/blob/v5/README.md#caching-packages-dependencies).

An exact cache-key hit is exposed in a named workflow step. A false value can
include a compatible fallback restoration; it does not prove zero cached bytes.
GitHub permits default-branch cache restoration under its normal access rules;
no privilege or cache-mode override is introduced. See
[GitHub cache matching and access rules](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching).

Before enabling caching, the repository API reported zero active caches and
a 10GB storage limit. That limit and all budget/runner settings remain unchanged.
Main runs can populate the normal cache; first cold runs may be slower.
Retain the optimization only if subsequent comparable warm runs repay cache
restore/save overhead. No measured saving is claimed yet.

Superseded runs of the same PR are cancelled. Each main push uses its own
concurrency group and keeps full validation. Actionlint 1.7.7 and whitespace
checks pass. Hosted cold/warm results and before/after timings are pending.
No unit-test execution is claimed from these workflow-only static checks.

## Contributor quick gate

Explicit `python3 scripts/setup-dev.py` installs existing dev dependencies into
`.venv` and enrolls the reviewed per-worktree hook. The quick adapter runs the
existing three registry-contract tests; no graph execution, formatter/linter/type
coverage or full-suite coverage is claimed. Full CI is unchanged. Actual local adoption results are recorded below; hosted after measurements
for this addition remain pending.

On 2026-11-01, `python3 scripts/setup-dev.py` completed in the actual linked
worktree, installed the dispatcher and its private enrollment marker, and left
Git configuration unchanged (Python 3.12.3). All 29 portable hook tests passed.
In an isolated repository with a local bare remote, a clean push passed the
three registry tests. A committed invalid listing slug failed one of them and
blocked the push without changing the remote ref; a corrected tip passed.
Missing `.venv` failed with the setup diagnostic, and the actual dirty parent
checkout was rejected. Fixture pushes used company author/committer metadata.
No live graph, provider, database, image or browser was invoked.

The temporary fixture reused the already prepared venv through an explicitly
ignored symlink. An initial missing-dependency control had accidentally tracked
that symlink and hit the dirty-tree guard instead; correcting the fixture ignore
made the intended missing-venv assertion pass. This did not require a product
code change. These are local adoption results, not hosted performance savings.
