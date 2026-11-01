#!/usr/bin/env python3
"""Install a shared dispatcher and enroll this worktree; no Git config writes."""
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile


def fail(message):
    raise SystemExit('pre-push install: ' + message)


def git(*args):
    return subprocess.check_output(['git', *args])


def git_path(*args):
    raw = git('rev-parse', *args)
    return Path(os.fsdecode(raw[:-1]))  # Remove only Git's final LF.


def publish_exclusive(path, data, mode):
    """No replacement, including symlinks and non-executable custom hooks."""
    if os.path.lexists(path):
        if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
            fail(f'existing {path!s} is not this dispatcher; preserve it and integrate manually')
        if mode & 0o100 and not os.access(path, os.X_OK):
            fail(f'{path!s} has matching bytes but is not executable; repair explicitly')
        return
    # Publish fully-written content without replacing a concurrent installation.
    fd, temporary = tempfile.mkstemp(prefix='.midkernel-prepush-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        try:
            os.link(temporary, path)
        except FileExistsError:
            fail('concurrent installer created destination; rerun after it finishes')
    finally:
        os.unlink(temporary)


def main():
    if git('rev-parse', '--is-bare-repository') != b'false\n':
        fail('requires a non-bare contributor checkout')
    root = git_path('--show-toplevel')
    os.chdir(root)
    configured = subprocess.run(['git', 'config', '--get', 'core.hooksPath'],
                                stdout=subprocess.DEVNULL)
    if configured.returncode == 0:
        fail('core.hooksPath is configured; no files/config changed. Integrate with its owner first')
    if configured.returncode != 1:
        fail('cannot read effective core.hooksPath')
    git_dir = git_path('--absolute-git-dir')
    common = git_path('--path-format=absolute', '--git-common-dir')
    hook = git_path('--path-format=absolute', '--git-path', 'hooks/pre-push')
    if not hook.is_absolute() or hook != common / 'hooks' / 'pre-push':
        fail('unexpected hooks resolution; requires Git >= 2.31 and default hooks path')
    if hook.parent.is_symlink():
        fail('hooks directory is a symlink; manual integration required')
    payload = root / 'scripts/prepush'
    for name in ('pre-push', 'check.py', 'quick-check.sh'):
        path = payload / name
        if path.is_symlink() or not path.is_file():
            fail(f'missing regular payload file: {path!s}')
    # Setup may run before new support files are committed. The gate still
    # requires a clean checkout before executing any checks.
    marker = git_dir / 'midkernel-prepush-v1'
    if os.path.lexists(marker) and (marker.is_symlink() or not marker.is_file()
                                  or marker.read_bytes() != b'v1\n'):
        fail('existing enrollment marker is not ours')
    hook.parent.mkdir(exist_ok=True, mode=0o700)
    publish_exclusive(hook, (payload / 'pre-push').read_bytes(), 0o700)
    publish_exclusive(marker, b'v1\n', 0o600)
    print(f'Installed/verified shared dispatcher: {hook}')
    print(f'Checks enabled only for this worktree: {root}')


if __name__ == '__main__':
    try:
        main()
    except (OSError, subprocess.CalledProcessError) as exc:
        fail(str(exc))
