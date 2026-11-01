#!/usr/bin/env python3
"""Offline only. Generates its own repos, code and local bare push destination."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

PAYLOAD = Path(__file__).resolve().parent
FIXTURES = os.environ.get('MIDKERNEL_PREPUSH_TEST_DIR')
os.umask(0o077)
QUICK = '''set -eu
[ -z "${AWS_ACCESS_KEY_ID:-}" ] || exit 98
[ -z "${OPENAI_API_KEY:-}" ] || exit 98
[ -z "${GIT_DIR:-}" ] || exit 98
printf ran >> "$(git rev-parse --git-path fixture-check-log)"
'''


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=FIXTURES, prefix='case-')
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.env = {k: os.environ[k] for k in ('PATH', 'LANG') if k in os.environ}
        self.env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=str(self.base/'no-global'),
                        GIT_TERMINAL_PROMPT='0', GIT_CONFIG_COUNT='0',
                        AWS_ACCESS_KEY_ID='synthetic-not-a-credential',
                        OPENAI_API_KEY='synthetic-not-a-credential')
        self.repo = self.base / "checkout space ' Unicode-λ\n"
        self.git(self.base, 'init', '--quiet', '--initial-branch=main', '--template=', str(self.repo))
        target = self.repo/'scripts/prepush'
        target.mkdir(parents=True)
        for name in ('pre-push','check.py','install.py'):
            shutil.copyfile(PAYLOAD/name, target/name)
        (target/'quick-check.sh').write_text(QUICK)
        (self.repo/'file.txt').write_text('initial\n')
        (self.repo/'.gitignore').write_text('ignored-cache/\n')
        self.commit()
        self.sha = self.git(self.repo,'rev-parse','HEAD').stdout.strip()

    def run_command(self, args, cwd, data=None, ok=True, extra=None):
        env = self.env | (extra or {})
        result = subprocess.run(args, cwd=cwd, env=env, input=data,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Keep every retained synthetic artifact private, including Git object files.
        for d, dirs, files in os.walk(self.base):
            os.chmod(d,0o700)
            for name in files:
                p=Path(d)/name
                if not p.is_symlink():
                    os.chmod(p,0o700 if p.stat().st_mode & 0o100 else 0o600)
        if ok and result.returncode:
            self.fail(f'{args!r}: {result.returncode}: {result.stderr.decode(errors="replace")}')
        return result

    def git(self, cwd, *args, ok=True):
        return self.run_command(['git', *args],cwd,ok=ok)

    def commit(self):
        self.git(self.repo,'add','--all')
        self.git(self.repo,'-c','user.name=Midkernel','-c','user.email=hello@midkernel.com',
                 '-c','commit.gpgsign=false','commit','--quiet','-m','synthetic fixture')

    def install(self, repo=None, ok=True):
        return self.run_command([sys.executable,'-I','scripts/prepush/install.py'],repo or self.repo,ok=ok)

    def line(self, oid=None, local=b'refs/heads/main', remote=b'refs/heads/main'):
        return b' '.join([local,oid or self.sha,remote,b'0'*len(self.sha)])+b'\n'

    def invoke(self, data=None, repo=None, ok=True):
        repo = repo or self.repo
        raw = self.git(repo,'rev-parse','--path-format=absolute','--git-path','hooks/pre-push').stdout
        hook = os.fsdecode(raw[:-1])
        return self.run_command([hook,'origin','fixture-local-only'],repo,
                                data=self.line() if data is None else data,ok=ok)

    def test_installed_hook_runs_and_is_idempotent_without_config_changes(self):
        before=(self.repo/'.git/config').read_bytes()
        self.install(); self.install(); self.invoke()
        self.assertEqual(before,(self.repo/'.git/config').read_bytes())
        self.assertEqual((self.repo/'.git/fixture-check-log').read_bytes(),b'ran')
        self.assertTrue(os.access(self.repo/'.git/hooks/pre-push',os.X_OK))

    def test_push_success_and_nonzero_prevents_local_remote_update(self):
        remote=self.base/'bare'; self.git(self.base,'init','--quiet','--bare','--template=',str(remote))
        self.install(); self.git(self.repo,'push',str(remote),'HEAD:refs/heads/main')
        prior=self.git(remote,'rev-parse','refs/heads/main').stdout
        (self.repo/'scripts/prepush/quick-check.sh').write_text('exit 23\n'); self.commit()
        result=self.git(self.repo,'push',str(remote),'HEAD:refs/heads/main',ok=False)
        self.assertNotEqual(result.returncode,0)
        self.assertIn(b'exit 23',result.stderr)
        self.assertEqual(self.git(remote,'rev-parse','refs/heads/main').stdout,prior)

    def test_checker_exit_code_propagates(self):
        (self.repo/'scripts/prepush/quick-check.sh').write_text('exit 23\n'); self.commit()
        self.sha=self.git(self.repo,'rev-parse','HEAD').stdout.strip(); self.install()
        self.assertEqual(self.invoke(ok=False).returncode,23)

    def test_missing_tool_fails_clearly(self):
        (self.repo/'scripts/prepush/quick-check.sh').write_text('set -eu\ncommand -v definitely_missing_midkernel_tool >/dev/null || { echo "missing fixture tool" >&2; exit 127; }\n')
        self.commit(); self.sha=self.git(self.repo,'rev-parse','HEAD').stdout.strip(); self.install()
        result=self.invoke(ok=False)
        self.assertEqual(result.returncode,127); self.assertIn(b'missing fixture tool',result.stderr)

    def test_custom_hook_and_symlink_preserved(self):
        hook=self.repo/'.git/hooks/pre-push'; hook.parent.mkdir()
        hook.write_text('custom no executable bit\n')
        self.assertNotEqual(self.install(ok=False).returncode,0)
        self.assertEqual(hook.read_text(),'custom no executable bit\n')
        hook.unlink(); hook.symlink_to(self.base/'nonexistent')
        self.assertNotEqual(self.install(ok=False).returncode,0)
        self.assertTrue(hook.is_symlink())
        self.assertFalse((self.repo/'.git/midkernel-prepush-v1').exists())

    def test_relative_absolute_and_global_hooks_paths_are_preserved(self):
        for path in ('custom hooks',str(self.base/'absolute hooks'),'/dev/null'):
            self.git(self.repo,'config','--local','core.hooksPath',path)
            before=(self.repo/'.git/config').read_bytes()
            self.assertNotEqual(self.install(ok=False).returncode,0)
            self.assertEqual(before,(self.repo/'.git/config').read_bytes())
        self.git(self.repo,'config','--unset','core.hooksPath')
        custom=self.base/'no-global'; custom.write_text('[core]\n hooksPath = relative-global\n')
        self.assertNotEqual(self.install(ok=False).returncode,0)
        self.assertFalse((self.repo/'.git/hooks/pre-push').exists())

    def test_linked_worktree_enrollment_is_private_and_does_not_enable_extension(self):
        other=self.base/'other tree'; self.git(self.repo,'worktree','add','--quiet','-b','other',str(other))
        before=(self.repo/'.git/config').read_bytes()
        self.install(other)
        self.invoke(repo=other)
        self.invoke(repo=self.repo)  # Unenrolled main checkout must no-op.
        self.assertFalse((self.repo/'.git/fixture-check-log').exists())
        self.assertEqual(before,(self.repo/'.git/config').read_bytes())
        self.install(); self.invoke()
        self.assertEqual((self.repo/'.git/fixture-check-log').read_bytes(),b'ran')
        gd=Path(os.fsdecode(self.git(other,'rev-parse','--absolute-git-dir').stdout[:-1]))
        self.assertEqual((gd/'fixture-check-log').read_bytes(),b'ran')

    def test_existing_worktree_config_is_preserved(self):
        self.git(self.repo,'config','extensions.worktreeConfig','true')
        self.git(self.repo,'config','--worktree','fixture.value','keep')
        before=(self.repo/'.git/config.worktree').read_bytes()
        self.install(); self.invoke()
        self.assertEqual(before,(self.repo/'.git/config.worktree').read_bytes())
        self.git(self.repo,'config','--worktree','core.hooksPath','custom-worktree')
        self.assertNotEqual(self.install(ok=False).returncode,0)

    def test_non_head_tags_multiple_and_malformed_rejected(self):
        self.install()
        for data in (self.line(b'1'*40), self.line(remote=b'refs/tags/new'),
                     self.line(local=b'refs/tags/lightweight'), self.line()+self.line(),
                     b'malformed\n', self.line(remote=b'refs/notes/example'),
                     self.line(local=b'refs/notes/example'), self.line(local=b'HEAD~0'),
                     self.line(remote=b'refs/heads/bad..name'),
                     self.line(local=b'refs/heads/bad..name')):
            self.assertNotEqual(self.invoke(data,ok=False).returncode,0)
        self.assertFalse((self.repo/'.git/fixture-check-log').exists())

    def test_empty_and_single_deletion_skip_checks_even_when_dirty(self):
        self.install(); (self.repo/'file.txt').write_text('dirty\n')
        self.invoke(b'')
        for remote in (b'refs/heads/old',b'refs/tags/old'):
            self.invoke(self.line(b'0'*40,local=b'(delete)',remote=remote))
        self.assertFalse((self.repo/'.git/fixture-check-log').exists())

    def test_staged_unstaged_and_untracked_dirty_block(self):
        self.install()
        (self.repo/'file.txt').write_text('dirty\n')
        self.assertNotEqual(self.invoke(ok=False).returncode,0)
        self.git(self.repo,'add','file.txt')
        self.assertNotEqual(self.invoke(ok=False).returncode,0)
        self.git(self.repo,'reset','--hard','HEAD')  # Synthetic fixture only.
        (self.repo/'untracked\nfile.txt').write_text('dirty\n')
        self.assertNotEqual(self.invoke(ok=False).returncode,0)

    def test_tracked_unusual_filenames_and_detached_head_work(self):
        for name in ('-leading.txt','white space.txt','line\nbreak.txt','λ.txt'):
            (self.repo/name).write_text('fixture\n')
        self.commit(); self.sha=self.git(self.repo,'rev-parse','HEAD').stdout.strip()
        self.git(self.repo,'checkout','--detach','--quiet'); self.install(); self.invoke()

    def test_assume_unchanged_and_skip_worktree_rejected(self):
        self.install()
        for flag in ('assume-unchanged','skip-worktree'):
            self.git(self.repo,'update-index','--'+flag,'file.txt')
            self.assertNotEqual(self.invoke(ok=False).returncode,0)
            self.git(self.repo,'update-index','--no-'+flag,'file.txt')

    def test_adapter_mutation_after_success_blocks_push(self):
        (self.repo/'scripts/prepush/quick-check.sh').write_text('printf changed >> file.txt\n')
        self.commit(); self.sha=self.git(self.repo,'rev-parse','HEAD').stdout.strip(); self.install()
        self.assertNotEqual(self.invoke(ok=False).returncode,0)

    def test_missing_adapter_on_old_branch_fails_closed(self):
        self.install(); self.git(self.repo,'rm','scripts/prepush/quick-check.sh'); self.commit()
        self.sha=self.git(self.repo,'rev-parse','HEAD').stdout.strip()
        self.assertNotEqual(self.invoke(ok=False).returncode,0)

    def test_ignored_inputs_are_explicitly_outside_cleanliness_guarantee(self):
        self.install(); (self.repo/'ignored-cache').mkdir()
        (self.repo/'ignored-cache/local.txt').write_text('local noncommitted input\n')
        self.invoke()  # Documented limitation; must not claim a hermetic commit snapshot.


    def test_symlink_hook_directory_is_preserved(self):
        external = self.base / 'external-hooks'
        external.mkdir()
        (self.repo / '.git/hooks').symlink_to(external, target_is_directory=True)
        self.assertNotEqual(self.install(ok=False).returncode, 0)
        self.assertEqual(list(external.iterdir()), [])
        self.assertFalse((self.repo / '.git/midkernel-prepush-v1').exists())

    def test_matching_non_executable_hook_requires_explicit_repair(self):
        self.install()
        hook = self.repo / '.git/hooks/pre-push'
        hook.chmod(0o600)
        self.assertNotEqual(self.install(ok=False).returncode, 0)
        self.assertFalse(os.access(hook, os.X_OK))

    def test_partial_install_can_be_retried_without_changing_hook(self):
        self.install()
        hook = self.repo / '.git/hooks/pre-push'
        inode = hook.stat().st_ino
        (self.repo / '.git/midkernel-prepush-v1').unlink()
        self.install()
        self.assertEqual(hook.stat().st_ino, inode)
        self.invoke()

    def test_invalid_marker_is_preserved_without_installation(self):
        marker = self.repo / '.git/midkernel-prepush-v1'
        marker.write_text('custom marker\n')
        self.assertNotEqual(self.install(ok=False).returncode, 0)
        self.assertEqual(marker.read_text(), 'custom marker\n')
        self.assertFalse((self.repo / '.git/hooks/pre-push').exists())

    def test_concurrent_installers_publish_only_complete_files(self):
        processes = [subprocess.Popen([sys.executable, '-I', 'scripts/prepush/install.py'],
                     cwd=self.repo, env=self.env, stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE) for _ in range(4)]
        outputs = [process.communicate(timeout=20) for process in processes]
        self.assertTrue(any(process.returncode == 0 for process in processes), outputs)
        self.install()
        self.assertEqual((self.repo / '.git/hooks/pre-push').read_bytes(),
                         (PAYLOAD / 'pre-push').read_bytes())
        self.assertEqual((self.repo / '.git/midkernel-prepush-v1').read_bytes(), b'v1\n')
        self.assertEqual(list((self.repo / '.git/hooks').glob('.midkernel-prepush-*')), [])
        self.invoke()

    def test_untracked_payload_can_install_but_cannot_pass_gate(self):
        self.git(self.repo, 'rm', '--cached', '-r', 'scripts/prepush')
        self.install()
        result = self.invoke(ok=False)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'commit/stash', result.stderr)

    def test_submodules_and_sparse_checkout_are_rejected(self):
        self.git(self.repo, 'update-index', '--add', '--cacheinfo',
                 '160000,' + self.sha.decode() + ',submodule')
        self.git(self.repo, '-c', 'user.name=Midkernel', '-c', 'user.email=hello@midkernel.com',
                 '-c', 'commit.gpgsign=false', 'commit', '--quiet', '-m', 'synthetic gitlink')
        self.sha = self.git(self.repo, 'rev-parse', 'HEAD').stdout.strip()
        self.install()
        result = self.invoke(ok=False)
        self.assertIn(b'submodules', result.stderr)
        self.git(self.repo, 'rm', '--cached', 'submodule')
        nested = self.repo / 'nested'
        nested.mkdir()
        (nested / 'file.txt').write_text('sparse fixture\n')
        self.commit()
        self.sha = self.git(self.repo, 'rev-parse', 'HEAD').stdout.strip()
        self.git(self.repo, 'sparse-checkout', 'init', '--cone')
        self.git(self.repo, 'sparse-checkout', 'set', 'scripts')
        self.assertIn(b'skip-worktree', self.invoke(ok=False).stderr)

    def test_changed_head_after_success_is_rejected(self):
        (self.repo / 'scripts/prepush/quick-check.sh').write_text('git update-ref HEAD HEAD^\n')
        self.commit()
        self.sha = self.git(self.repo, 'rev-parse', 'HEAD').stdout.strip()
        self.install()
        self.assertIn(b'HEAD changed', self.invoke(ok=False).stderr)

    def test_missing_gate_and_adapter_symlinks_are_rejected(self):
        self.install()
        gate = self.repo / 'scripts/prepush/check.py'
        gate.unlink()
        self.assertIn(b'lacks scripts/prepush/check.py', self.invoke(ok=False).stderr)
        gate.symlink_to(PAYLOAD / 'check.py')
        self.assertIn(b'lacks scripts/prepush/check.py', self.invoke(ok=False).stderr)
        gate.unlink()
        shutil.copyfile(PAYLOAD / 'check.py', gate)
        adapter = self.repo / 'scripts/prepush/quick-check.sh'
        adapter.unlink()
        adapter.symlink_to(PAYLOAD / 'quick-check.sh')
        self.commit()
        self.sha = self.git(self.repo, 'rev-parse', 'HEAD').stdout.strip()
        self.assertIn(b'missing regular quick-check.sh', self.invoke(ok=False).stderr)

    def test_missing_python_and_git_errors_fail_closed(self):
        self.install()
        bin_dir = self.base / 'bin'
        bin_dir.mkdir()
        (bin_dir / 'git').symlink_to(shutil.which('git'))
        hook = self.repo / '.git/hooks/pre-push'
        result = self.run_command([str(hook)], self.repo, data=self.line(), ok=False,
                                  extra={'PATH': str(bin_dir)})
        self.assertEqual(result.returncode, 127)
        self.assertIn(b'Python 3 is required', result.stderr)
        result = self.run_command([str(hook)], self.repo, data=self.line(), ok=False,
                                  extra={'GIT_INDEX_FILE': str(self.base / 'bad-index')})
        # A missing index also differs from HEAD; a damaged index is a hard Git error.
        self.assertNotEqual(result.returncode, 0)
        (self.base / 'bad-index').write_text('invalid index\n')
        result = self.run_command([str(hook)], self.repo, data=self.line(), ok=False,
                                  extra={'GIT_INDEX_FILE': str(self.base / 'bad-index')})
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'pre-push:', result.stderr)

    def test_explicit_head_and_full_oid_are_supported(self):
        self.install()
        self.invoke(self.line(local=b'HEAD'))
        self.invoke(self.line(local=self.sha))

    def test_sha256_repository_is_supported(self):
        other = self.base / 'sha256'
        self.git(self.base, 'init', '--quiet', '--object-format=sha256',
                 '--initial-branch=main', '--template=', str(other))
        shutil.copytree(self.repo / 'scripts', other / 'scripts')
        self.repo = other
        self.commit()
        self.sha = self.git(self.repo, 'rev-parse', 'HEAD').stdout.strip()
        self.assertEqual(len(self.sha), 64)
        self.install()
        self.invoke()

    def test_no_verify_is_an_explicit_bypass(self):
        remote = self.base / 'bare'
        self.git(self.base, 'init', '--quiet', '--bare', '--template=', str(remote))
        (self.repo / 'scripts/prepush/quick-check.sh').write_text('exit 23\n')
        self.commit()
        self.install()
        self.git(self.repo, 'push', str(remote), 'HEAD:refs/heads/main', ok=False)
        self.assertNotEqual(self.git(remote, 'rev-parse', '--verify',
                                    'refs/heads/main', ok=False).returncode, 0)
        self.git(self.repo, 'push', '--no-verify', str(remote), 'HEAD:refs/heads/main')
        self.assertEqual(self.git(remote, 'rev-parse', 'refs/heads/main').stdout,
                         self.git(self.repo, 'rev-parse', 'HEAD').stdout)


if __name__ == '__main__':
    unittest.main(verbosity=2)
