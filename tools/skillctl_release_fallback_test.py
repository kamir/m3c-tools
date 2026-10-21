#!/usr/bin/env python3
"""Offline adversarial orchestration tests; real OpenSSL, mocked GitHub/Sigstore/SLSA."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

SPEC = importlib.util.spec_from_file_location("fallback", Path(__file__).with_name("skillctl_release_fallback.py"))
m = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(m)
TAG = "skillctl/v0.5.1-rc1"
SHA = "a" * 40


class FallbackTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = tempfile.TemporaryDirectory(prefix="fallback-synthetic-keys-")
        cls.key = Path(cls.keys.name) / "test.key"
        cls.pub = Path(cls.keys.name) / "test.pub"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(cls.key)], check=True)
        subprocess.run(["openssl", "pkey", "-in", str(cls.key), "-pubout", "-out", str(cls.pub)], check=True)
        der = subprocess.check_output(["openssl", "pkey", "-pubin", "-in", str(cls.pub), "-outform", "DER"])
        cls.fp = hashlib.sha256(der[12:]).hexdigest()

    @classmethod
    def tearDownClass(cls):
        cls.keys.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="fallback-test-home-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "INFRA").mkdir()
        (self.root / "INFRA/skillctl-release.pub").write_bytes(self.pub.read_bytes())
        self.events = []
        self.tag_reads = 0
        self.change_tag = False
        self.fail_tool = None
        self.mutate_manifest = None
        self.mutate_statement = lambda s: None
        self.mutate_assets = lambda a: a
        self.mutate_sizes = lambda name, size: size
        self.real_run = m.run
        self.env = patch.dict(os.environ, {"HOME": str(self.root), "USERPROFILE": str(self.root),
                              "RELEASE_KEY": str(self.key), "M3C_TOKEN_STORE": "file",
                              "M3C_ER1_KEYCHAIN": "off", "M3C_TEST_KEYCHAIN": "0",
                              "THOH_PUBLISH": "1"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def statement(self):
        s = {"_type": "https://in-toto.io/Statement/v0.1",
             "predicateType": "https://slsa.dev/provenance/v0.2",
             "subject": [{"name": name, "digest": {"sha256": hashlib.sha256((name + " CI bytes\n").encode()).hexdigest()}} for name in m.BINARIES],
             "predicate": {"builder": {"id": m.BUILDER}, "invocation": {
                 "configSource": {"uri": "git+https://github.com/" + m.REPO,
                                  "digest": {"sha1": SHA}, "entryPoint": m.WORKFLOW},
                 "environment": {"github_sha1": SHA, "github_ref": "refs/tags/" + TAG}}}}
        self.mutate_statement(s)
        return json.dumps(s).encode()

    def api(self, endpoint):
        self.events.append(("api", endpoint))
        if endpoint.startswith("git/ref/"):
            self.tag_reads += 1
            return {"object": {"type": "commit", "sha": "b" * 40 if self.change_tag and self.tag_reads > 1 else SHA}}
        assets = list(m.BINARIES) + ["SHA256SUMS", "SHA256SUMS.cosign.bundle", "multiple.intoto.jsonl"]
        sizes = {name: len((name + " CI bytes\n").encode()) for name in m.BINARIES}
        sizes.update({"SHA256SUMS": sum(64 + 2 + len(name) + 1 for name in m.BINARIES),
                      "SHA256SUMS.cosign.bundle": len(b"mock cosign bundle"),
                      "multiple.intoto.jsonl": len(b"mock slsa bundle")})
        return {"tag_name": TAG, "assets": [{"name": x, "size": self.mutate_sizes(x, sizes.get(x, 1))}
                                           for x in self.mutate_assets(assets)]}

    def external_run(self, args):
        self.events.append(tuple(args))
        if args[0] == self.fail_tool:
            raise subprocess.CalledProcessError(1, args)
        if args[:3] == ["gh", "release", "download"]:
            stage = Path(args[args.index("--dir") + 1])
            self.original = b""
            for name in m.BINARIES:
                raw = (name + " CI bytes\n").encode()
                (stage / name).write_bytes(raw)
                self.original += hashlib.sha256(raw).hexdigest().encode() + b"  " + name.encode() + b"\n"
            (stage / "SHA256SUMS").write_bytes(self.original)
            (stage / "SHA256SUMS.cosign.bundle").write_bytes(b"mock cosign bundle")
            (stage / "multiple.intoto.jsonl").write_bytes(b"mock slsa bundle")
            if self.mutate_manifest:
                self.mutate_manifest(stage)
            return b""
        if args[0] == "slsa-verifier":
            self.assertIn("--source-tag", args)
            self.assertEqual(args[args.index("--source-tag") + 1], TAG)
            self.assertIn("--print-provenance", args)
            return self.statement()
        if args[0] == "cosign":
            self.assertEqual(args[args.index("--certificate-identity") + 1],
                             f"https://github.com/{m.REPO}/{m.WORKFLOW}@refs/tags/{TAG}")
            self.assertNotIn("--certificate-identity-regexp", args)
            return b""
        return self.real_run(args)

    def execute(self, tag=TAG):
        with patch.object(m, "PUBLIC_FP", self.fp), patch.object(m.shutil, "which", return_value="present"), \
             patch.object(m, "api", side_effect=self.api), patch.object(m, "run", side_effect=self.external_run):
            m.prepare(tag, self.root)

    def assert_refused_before_sign(self, tag=TAG):
        with self.assertRaises((m.VerificationError, subprocess.CalledProcessError)):
            self.execute(tag)
        self.assertFalse(any("-sign" in event or "-inkey" in event for event in self.events), self.events)
        self.assertFalse((self.root / "release").exists())

    def test_exact_ci_bytes_signed_real_ed25519(self):
        self.execute()
        out = self.root / "release" / TAG
        self.assertEqual((out / "SHA256SUMS").read_bytes(), self.original)
        subprocess.run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(self.pub),
                        "-rawin", "-in", str(out / "SHA256SUMS"), "-sigfile", str(out / "SHA256SUMS.sig")], check=True)
        self.assertEqual(len(list(out.iterdir())), 10)
        self.assertEqual(sum(e[0] == "slsa-verifier" for e in self.events), 5)
        self.assertFalse(any(e[0] in ("go", "curl") or "upload" in e or "create" in e for e in self.events))
        self.assertEqual(self.tag_reads, 2)

    def test_invalid_tags_before_any_commands(self):
        for tag in ("skillctl/../../oops", "--help", "skillctl/v1.2.3/xx", "skillctl/v1.2.3\n", "skillctl/v01.2.3", "skillctl/v1.2.3;id"):
            self.events.clear()
            self.assert_refused_before_sign(tag)
            self.assertEqual(self.events, [])

    def test_missing_tool(self):
        with patch.object(m.shutil, "which", return_value=None), patch.object(m, "run") as run:
            with self.assertRaises(m.VerificationError):
                m.prepare(TAG, self.root)
            run.assert_not_called()

    def test_cosign_rejection(self):
        self.fail_tool = "cosign"
        self.assert_refused_before_sign()

    def test_slsa_rejection(self):
        self.fail_tool = "slsa-verifier"
        self.assert_refused_before_sign()

    def test_download_rejection(self):
        self.fail_tool = "gh"
        self.assert_refused_before_sign()

    def test_tag_retarget(self):
        self.change_tag = True
        self.assert_refused_before_sign()

    def test_exact_source_sha(self):
        self.mutate_statement = lambda s: s["predicate"]["invocation"]["configSource"]["digest"].update(sha1="b" * 40)
        self.assert_refused_before_sign()

    def test_environment_sha(self):
        self.mutate_statement = lambda s: s["predicate"]["invocation"]["environment"].update(github_sha1="b" * 40)
        self.assert_refused_before_sign()

    def test_environment_tag(self):
        self.mutate_statement = lambda s: s["predicate"]["invocation"]["environment"].update(github_ref="refs/heads/master")
        self.assert_refused_before_sign()

    def test_workflow(self):
        self.mutate_statement = lambda s: s["predicate"]["invocation"]["configSource"].update(entryPoint="other.yml")
        self.assert_refused_before_sign()

    def test_builder(self):
        self.mutate_statement = lambda s: s["predicate"]["builder"].update(id="other")
        self.assert_refused_before_sign()

    def test_wrong_subject_digest(self):
        self.mutate_statement = lambda s: s["subject"][0]["digest"].update(sha256="0" * 64)
        self.assert_refused_before_sign()

    def test_duplicate_manifest_name(self):
        def mutate(stage):
            p = stage / "SHA256SUMS"
            lines = p.read_bytes().splitlines(keepends=True)
            p.write_bytes(b"".join([lines[0], lines[0]] + lines[2:]))
        self.mutate_manifest = mutate
        self.assert_refused_before_sign()

    def test_noncanonical_manifest(self):
        def mutate(stage):
            p = stage / "SHA256SUMS"
            p.write_bytes(p.read_bytes().replace(b"\n", b"\r\n"))
        self.mutate_manifest = mutate
        self.assert_refused_before_sign()

    def test_manifest_traversal(self):
        def mutate(stage):
            p = stage / "SHA256SUMS"
            p.write_bytes(p.read_bytes().replace(m.BINARIES[0].encode(), b"../outside"))
        self.mutate_manifest = mutate
        self.assert_refused_before_sign()

    def test_extra_manifest_entry(self):
        def mutate(stage):
            p = stage / "SHA256SUMS"
            p.write_bytes(p.read_bytes() + b"0" * 64 + b"  extra\n")
        self.mutate_manifest = mutate
        self.assert_refused_before_sign()

    def test_multiple_provenance_assets(self):
        self.mutate_assets = lambda assets: assets + ["other.intoto.jsonl"]
        self.assert_refused_before_sign()

    def test_symlink_output_parent(self):
        (self.root / "release").symlink_to(self.root / "INFRA", target_is_directory=True)
        with self.assertRaises(m.VerificationError):
            self.execute()
        self.assertEqual(self.events, [])

    def test_annotated_tag_resolution(self):
        with patch.object(m, "api", side_effect=[
                {"object": {"type": "tag", "sha": "b" * 40}},
                {"object": {"type": "commit", "sha": SHA}}]) as api:
            self.assertEqual(m.tag_commit(TAG), SHA)
            self.assertEqual(api.call_count, 2)

    def test_unresolvable_tag(self):
        with patch.object(m, "api", return_value={"object": {"type": "tree", "sha": SHA}}):
            with self.assertRaises(m.VerificationError):
                m.tag_commit(TAG)

    def test_checksum_mismatch(self):
        self.mutate_manifest = lambda stage: (stage / m.BINARIES[0]).write_bytes(b"local build")
        self.assert_refused_before_sign()

    def test_symlink_binary(self):
        def mutate(stage):
            p = stage / m.BINARIES[0]
            p.unlink()
            p.symlink_to(self.pub)
        self.mutate_manifest = mutate
        self.assert_refused_before_sign()

    def test_missing_asset(self):
        self.mutate_assets = lambda assets: assets[:-1]
        self.assert_refused_before_sign()

    def test_duplicate_asset(self):
        self.mutate_assets = lambda assets: assets + [assets[0]]
        self.assert_refused_before_sign()

    def test_wrong_pinned_public_key(self):
        (self.root / "INFRA/skillctl-release.pub").write_text("not a public key")
        self.assert_refused_before_sign()

    def test_wrong_signing_key_real_openssl(self):
        other = self.root / "wrong-test.key"
        subprocess.run(["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(other)], check=True)
        with patch.dict(os.environ, {"RELEASE_KEY": str(other)}):
            with self.assertRaises(subprocess.CalledProcessError):
                self.execute()
        self.assertFalse((self.root / "release").exists())

    def test_existing_output(self):
        out = self.root / "release" / TAG
        out.mkdir(parents=True)
        (out / "keep").write_text("do not overwrite")
        with self.assertRaises(m.VerificationError):
            self.execute()
        self.assertEqual((out / "keep").read_text(), "do not overwrite")
        self.assertEqual(self.events, [])

    def test_asset_size_metadata_overflow(self):
        self.mutate_sizes = lambda name, size: m.MAX_BINARY + 1 if name in m.BINARIES else size
        self.assert_refused_before_sign()
        self.assertFalse(any(e[0] == "gh" for e in self.events))

    def test_asset_size_bool(self):
        self.mutate_sizes = lambda name, size: True
        self.assert_refused_before_sign()

    def test_asset_size_download_mismatch(self):
        self.mutate_sizes = lambda name, size: size + 1
        self.assert_refused_before_sign()

    def test_real_download_subprocess_file_limit(self):
        # Execute only a local fake downloader, not gh/network or a release binary.
        bindir = self.root / "fake-bin"
        bindir.mkdir()
        downloader = bindir / "gh"
        target = self.root / "bounded-download"
        downloader.write_text("#!/usr/bin/env python3\nfrom pathlib import Path\nPath(" +
                              repr(str(target)) + ").write_bytes(b'x' * 2048)\n")
        downloader.chmod(0o700)
        with patch.dict(os.environ, {"PATH": str(bindir) + os.pathsep + os.environ["PATH"]}), \
             patch.object(m, "MAX_BINARY", 1024):
            with self.assertRaises(subprocess.CalledProcessError):
                self.real_run(["gh", "release", "download"])
        self.assertLessEqual(target.stat().st_size, 1024)

    def test_output_copy_failure_cleanup(self):
        with patch.object(m.shutil, "copyfile", side_effect=OSError("simulated disk failure")):
            with self.assertRaises(OSError):
                self.execute()
        self.assertFalse((self.root / "release" / TAG).exists())

    def test_duplicate_statement_keys(self):
        with self.assertRaises(m.VerificationError):
            m.strict_json('{"predicate":{},"predicate":{}}')


if __name__ == "__main__":
    unittest.main()
