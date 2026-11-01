#!/usr/bin/env python3
"""One HEAD branch update, clean source, explicit repository quick-check adapter."""
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def fail(message):
    raise SystemExit('pre-push: ' + message)


def git(*args):
    return subprocess.check_output(['git', '--no-replace-objects',
                                   '-c', 'core.fsmonitor=false', *args])


def head():
    return git('rev-parse', '--verify', 'HEAD^{commit}').rstrip(b'\n')


def clean(expected):
    if head() != expected:
        fail('HEAD changed; retry from the commit being pushed')
    # Reject index modes where a normal clean-status check is insufficient.
    for entry in git('ls-files', '-v', '-z').split(b'\0'):
        if entry and entry[:1] != b'H':
            fail('requires a full checkout without assume-unchanged/skip-worktree entries')
    for entry in git('ls-files', '--stage', '-z').split(b'\0'):
        if entry.startswith(b'160000 '):
            fail('submodules need a reviewed repository-specific check; unsupported in v1')
    if git('status', '--porcelain=v1', '-z', '--untracked-files=all',
           '--ignore-submodules=none'):
        fail('commit/stash tracked changes and nonignored untracked files, then retry; nothing was stashed')
    # Recheck against HEAD without external diff/textconv. This is still Git's
    # ordinary worktree comparison, not a hermetic snapshot or race barrier.
    subprocess.run(['git', '--no-replace-objects', '-c', 'core.fsmonitor=false',
                    'diff', '--quiet', '--no-ext-diff', '--no-textconv', 'HEAD', '--'],
                   check=True)


def main():
    rows = sys.stdin.buffer.read().splitlines()
    if not rows:
        return 0  # No updated refs.
    if len(rows) != 1:
        fail('push one ref at a time; multiple refs/--all/--mirror/--follow-tags batches are unsupported')
    fields = rows[0].split(b' ')
    if len(fields) != 4 or not all(fields):
        fail('invalid pre-push input')
    local_ref, local_oid, remote_ref, remote_oid = fields
    if (not re.fullmatch(b'(?:[0-9a-f]{40}|[0-9a-f]{64})', local_oid)
            or not re.fullmatch(b'[0-9a-f]{' + str(len(local_oid)).encode() + b'}', remote_oid)):
        fail('invalid object ID in pre-push input')
    if not remote_ref.startswith((b'refs/heads/', b'refs/tags/')):
        fail('only branch updates or a single branch/tag deletion are supported')
    if subprocess.run(['git', 'check-ref-format', os.fsdecode(remote_ref)],
                      stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
        fail('invalid destination ref in pre-push input')
    if local_oid == b'0' * len(local_oid):
        if local_ref != b'(delete)':
            fail('invalid deletion input')
        return 0  # Deletion pushes no source content.
    if remote_ref.startswith(b'refs/tags/') or local_ref.startswith(b'refs/tags/'):
        fail('tag creation/update is outside this quick gate; use the reviewed release procedure')
    if local_ref.startswith(b'refs/heads/'):
        if subprocess.run(['git', 'check-ref-format', os.fsdecode(local_ref)],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
            fail('invalid source branch in pre-push input')
    elif local_ref != b'HEAD' and local_ref != local_oid:
        fail('unsupported source; push a branch, HEAD or its full object ID')
    if git('rev-parse', '--is-bare-repository') != b'false\n':
        fail('requires a contributor worktree')
    expected = head()
    if local_oid != expected:
        fail('pushed commit is not HEAD; check out that commit in its own prepared worktree and retry')
    root = Path(os.fsdecode(git('rev-parse', '--show-toplevel')[:-1]))
    os.chdir(root)
    clean(expected)
    adapter = root / 'scripts/prepush/quick-check.sh'
    if adapter.is_symlink() or not adapter.is_file():
        fail('missing regular quick-check.sh; rerun contributor setup on a supported branch')
    git_dir = Path(os.fsdecode(git('rev-parse', '--absolute-git-dir')[:-1]))
    with tempfile.TemporaryDirectory(prefix='midkernel-prepush-', dir=git_dir) as temporary:
        # Fixed noncredential environment. Git repository-selection variables are
        # deliberately not forwarded to checks that may inspect another local repo.
        environment = {
            'PATH': os.environ.get('PATH', '/usr/bin:/bin'), 'LANG': 'C.UTF-8',
            'HOME': temporary,
            'TMPDIR': temporary, 'XDG_CACHE_HOME': temporary,
            'XDG_CONFIG_HOME': temporary, 'PYTHONDONTWRITEBYTECODE': '1',
            'PYTHONNOUSERSITE': '1', 'GIT_TERMINAL_PROMPT': '0',
            'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_GLOBAL': os.devnull,
        }
        result = subprocess.run(['/bin/sh', str(adapter)], cwd=root,
                                env=environment, stdin=subprocess.DEVNULL)
    if result.returncode:
        print(f'pre-push: quick checks failed (exit {result.returncode}); push blocked', file=sys.stderr)
        return result.returncode if result.returncode > 0 else 128 - result.returncode
    clean(expected)
    print('pre-push: quick checks passed for clean HEAD ' + expected.decode(), file=sys.stderr)
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(str(exc))
