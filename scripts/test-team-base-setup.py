#!/usr/bin/env python3
"""Exercise team setup against an explicitly supplied real skillctl binary.

Usage: python3 scripts/test-team-base-setup.py --skillctl /absolute/path/skillctl
The suite uses disposable profiles and does not download binaries or models.
"""
import argparse
import os
import re
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

parser = argparse.ArgumentParser()
parser.add_argument('--skillctl', required=True)
args = parser.parse_args()
BINARY = str(Path(args.skillctl).resolve())
SCRIPT = Path(__file__).resolve().parents[1] / 'tools/team-base-setup.sh'


@unittest.skipIf(os.name == 'nt', 'Unix setup wrapper requires bash')
class TeamSetupTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='team-setup-')
        self.root = Path(self.temp.name).resolve()
        self.home = self.root / 'home'
        self.home.mkdir()
        self.workspace = self.root / 'workspace'
        self.env = dict(os.environ, HOME=str(self.home), USERPROFILE=str(self.home),
                        M3C_ER1_KEYCHAIN='off', M3C_TOKEN_STORE='file',
                        SKILLCTL_NO_SERVICE='1', SKILLCTL=BINARY)
        self.key = self.root / 'bob'
        self.cli('keygen', '--out', self.key)
        self.pin = self.cli('trust', 'fingerprint', str(self.key)+'.pub').stdout.strip()

    def tearDown(self):
        self.temp.cleanup()

    def cli(self, *argv):
        p = subprocess.run([BINARY, *map(str, argv)], env=self.env,
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(p.returncode, 0, p.stdout+p.stderr)
        return p

    def setup(self, role, *extra):
        return subprocess.run(['bash', str(SCRIPT), role, '--workspace', str(self.workspace),
                               *map(str, extra)], env=self.env, capture_output=True,
                              text=True, timeout=30)

    def member(self, *extra):
        return self.setup('member', '--author-id', 'id:bob@example', '--author-key',
                          str(self.key)+'.pub', '--pin', self.pin,
                          '--peer-registry', 'local://'+str(self.root/'registry.git'), *extra)

    def test_author_repeat_keeps_key_and_custom_rules(self):
        self.assertEqual(self.setup('author', '--id', 'id:bob@example').returncode, 0)
        key = self.workspace/'keys/author.priv'
        original = key.read_bytes()
        rules = self.workspace/'CLAUDE.md'
        rules.write_text('Human rules\n')
        self.assertEqual(self.setup('author', '--id', 'id:bob@example').returncode, 0)
        self.assertEqual(key.read_bytes(), original)
        self.assertEqual(rules.read_text(), 'Human rules\n')
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)

    def test_invalid_contexts_leave_no_workspace(self):
        for context in ('', ',', 'a,,b', ' ', '..', '../escape', 'a/b', '/absolute'):
            with self.subTest(context=context):
                result = self.setup('author', '--id', 'id:bob@example', '--contexts', context)
                self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
                self.assertFalse(self.workspace.exists())

    def test_blocking_directory_type_is_rejected_before_other_writes(self):
        self.workspace.mkdir()
        (self.workspace/'keys').write_text('not a directory')
        self.assertEqual(self.setup('author', '--id', 'id:bob@example').returncode, 1)
        self.assertFalse((self.workspace/'CLAUDE.md').exists())

    def test_following_option_is_not_consumed_as_a_value(self):
        for option in ('--id', '--contexts', '--workspace'):
            result = self.setup('author', '--id', 'id:bob@example', option, '--dry-run')
            self.assertEqual(result.returncode, 2, result.stdout+result.stderr)
            self.assertFalse(self.workspace.exists())

    def test_context_readme_directory_is_rejected_before_pins(self):
        (self.workspace/'contexts/allgemein/README.md').mkdir(parents=True)
        self.assertEqual(self.member().returncode, 1)
        self.assertFalse((self.home/'.claude').exists())
        self.assertFalse((self.workspace/'contexts/allgemein/inbox').exists())

    def test_registry_path_with_spaces_can_be_repeated(self):
        path = 'local://'+str(self.root/'registry with  spaces.git')
        result = self.member('--peer-registry', path)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        result = self.member('--peer-registry', path)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)

    def test_peer_only_requires_registry(self):
        result = self.setup('member', '--author-id', 'id:bob@example', '--author-key',
                            str(self.key)+'.pub', '--pin', self.pin, '--peer-only')
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.workspace.exists())
        self.assertFalse((self.home/'.claude').exists())

    def test_peer_only_preserves_unrelated_http_roots(self):
        self.cli('trust', 'add', '--registry', 'https://unrelated.example/api/skills',
                 '--pubkey', str(self.key)+'.pub')
        path = self.home/'.claude/skill-trust-roots.yaml'
        before = path.read_bytes()
        result = self.member('--peer-only')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(path.read_bytes(), before)

    def test_peer_only_reviewer_install_and_verify_offline(self):
        registry = 'local://'+str(self.root/'registry.git')
        self.cli('registry', 'init', '--registry', registry)
        self.cli('keygen', '--out', self.root/'charlie')
        author = self.cli('trust', 'fingerprint', '--b64', str(self.key)+'.pub').stdout.strip()
        reviewer = self.cli('trust', 'fingerprint', '--b64', self.root/'charlie.pub').stdout.strip()
        self.cli('peer', 'add', 'bob@example', registry, '--pubkey', author, '--pin', self.pin,
                 '--signer', 'id:charlie@example:'+reviewer, '--quorum', '1')
        peers = self.home/'.claude/skill-peers.yaml'
        before = peers.read_bytes()
        result = self.member('--peer-only')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual(peers.read_bytes(), before)
        self.assertFalse((self.home/'.claude/skill-trust-roots.yaml').exists())
        source = self.root/'source'
        source.mkdir()
        (source/'SKILL.md').write_text('---\nname: wochenbericht\ndescription: Local weekly report fixture.\n---\nSummarize the supplied sources.\n')
        bundle = self.root/'wochenbericht.skb'
        self.cli('pack', '--skill', source, '-o', bundle, '--name', 'wochenbericht', '--version', '1.0.0')
        signed = self.cli('sign', '--key', str(self.key)+'.priv', bundle)
        digest = 'sha256:'+re.search(r'^digest:\s*(\S+)', signed.stdout, re.M)[1]
        self.cli('publish', 'wochenbericht@1.0.0', '--bundle', bundle, '--version', '1.0.0',
                 '--registry', registry, '--key', str(self.key)+'.priv', '--identity', 'id:bob@example', '--yes')
        self.cli('publish', '--attest', 'wochenbericht@1.0.0', '--digest', digest, '--level', 'green',
                 '--rationale', 'Reviewed synthetic fixture', '--registry', registry,
                 '--key', self.root/'charlie.priv', '--identity', 'id:charlie@example', '--yes')
        pull = ['pull', '--registry', registry, '--skill', 'wochenbericht', '--install', '--trust-mode', '--no-checkpoint']
        plan = self.cli(*pull, '--dry-run-install')
        token = re.search(r'token \(5-minute TTL\): (\S+)', plan.stdout+plan.stderr)[1]
        self.cli(*pull, '--confirm-install', '--dry-run-install-token', token)
        verified = self.cli('verify', 'wochenbericht')
        self.assertIn('offline', verified.stdout)
        self.assertNotIn('author.example', verified.stdout+verified.stderr)

    def test_existing_mismatched_keypair_is_rejected(self):
        directory = self.workspace/'keys'
        directory.mkdir(parents=True)
        shutil.copyfile(str(self.key)+'.priv', directory/'author.priv')
        os.chmod(directory/'author.priv', 0o600)
        self.cli('keygen', '--out', self.root/'other')
        shutil.copyfile(self.root/'other.pub', directory/'author.pub')
        result = self.setup('author', '--id', 'id:bob@example')
        self.assertEqual(result.returncode, 1, result.stdout+result.stderr)
        self.assertFalse((self.workspace/'CLAUDE.md').exists())

    def test_context_symlink_does_not_redirect_writes(self):
        (self.workspace/'contexts').mkdir(parents=True)
        outside = self.root/'outside'
        outside.mkdir()
        (self.workspace/'contexts/allgemein').symlink_to(outside, target_is_directory=True)
        self.assertEqual(self.setup('author', '--id', 'id:bob@example').returncode, 1)
        self.assertEqual(list(outside.iterdir()), [])
        self.assertFalse((self.workspace/'keys').exists())

    def test_missing_member_arguments_do_not_create_workspace(self):
        self.assertEqual(self.setup('member').returncode, 2)
        self.assertFalse(self.workspace.exists())
        self.assertFalse((self.home/'.claude').exists())

    def test_wrong_pin_does_not_create_trust_or_workspace(self):
        result = self.member('--pin', 'sha256:'+'0'*64)
        self.assertEqual(result.returncode, 1)
        self.assertFalse((self.home/'.claude').exists())
        self.assertFalse(self.workspace.exists())

    def test_member_repeat_preserves_pin_files(self):
        result = self.member()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        paths = [self.home/'.claude'/name for name in
                 ('skill-trust-roots.yaml', 'skill-peers.yaml')]
        before = [p.read_bytes() for p in paths]
        result = self.member()
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertEqual([p.read_bytes() for p in paths], before)

    def test_existing_other_key_is_not_overwritten(self):
        self.assertEqual(self.member().returncode, 0)
        path = self.home/'.claude/skill-trust-roots.yaml'
        before = path.read_bytes()
        self.cli('keygen', '--out', self.root/'other')
        otherpin = self.cli('trust', 'fingerprint', self.root/'other.pub').stdout.strip()
        result = self.member('--author-key', self.root/'other.pub', '--pin', otherpin)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(path.read_bytes(), before)

    def test_separate_registry_key_needs_confirmed_pin(self):
        self.cli('keygen', '--out', self.root/'diana')
        public = self.root/'diana.pub'
        result = self.member('--registry-key', public)
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.home/'.claude').exists())
        pin = self.cli('trust', 'fingerprint', public).stdout.strip()
        result = self.member('--registry-key', public, '--registry-pin', pin)
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertIn(pin, self.cli('peer', 'ls').stdout)

    def test_dry_run_leaves_actual_profile_unchanged(self):
        result = self.member('--dry-run')
        self.assertEqual(result.returncode, 0, result.stdout+result.stderr)
        self.assertFalse((self.home/'.claude').exists())
        self.assertFalse(self.workspace.exists())
        self.assertNotIn('Workspace ready:', result.stdout)

    def test_check_detects_broken_existing_author_keypair(self):
        self.assertEqual(self.setup('author', '--id', 'id:bob@example').returncode, 0)
        self.cli('keygen', '--out', self.root/'other')
        shutil.copyfile(self.root/'other.pub', self.workspace/'keys/author.pub')
        self.assertEqual(self.setup('check').returncode, 1)

    def test_check_missing_workspace_reports_failure(self):
        self.assertEqual(self.setup('check').returncode, 1)

    def test_existing_incomplete_or_unsafe_keypair_reports_failure(self):
        directory = self.workspace/'keys'
        directory.mkdir(parents=True)
        shutil.copyfile(str(self.key)+'.priv', directory/'author.priv')
        os.chmod(directory/'author.priv', 0o600)
        self.assertEqual(self.setup('author', '--id', 'id:bob@example').returncode, 1)
        shutil.copyfile(str(self.key)+'.pub', directory/'author.pub')
        os.chmod(directory/'author.priv', 0o644)
        self.assertEqual(self.setup('author', '--id', 'id:bob@example').returncode, 1)
        self.assertFalse((self.workspace/'CLAUDE.md').exists())


unittest.main(argv=[__file__], verbosity=2)
