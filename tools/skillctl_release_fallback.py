#!/usr/bin/env python3
"""Fail-closed local fallback signing of existing CI release manifest bytes."""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import sys
import tempfile
from urllib.parse import quote

REPO = "kamir/m3c-tools"
WORKFLOW = ".github/workflows/skillctl-release.yml"
BUILDER = ("https://github.com/slsa-framework/slsa-github-generator/"
           ".github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0")
PUBLIC_FP = "5f8f39cb0454dcd8ac04c6729af2fa4b71a13a5e125e56924701d9e38187a9c2"
MAX_BINARY = 128 * 1024 * 1024
MAX_METADATA = 4 * 1024 * 1024
MAX_TOTAL = 512 * 1024 * 1024
BINARIES = ("skillctl-darwin-arm64", "skillctl-darwin-amd64", "skillctl-linux-amd64",
            "skillctl-linux-arm64", "skillctl-windows-amd64.exe")
# Existing rc tags use e.g. skillctl/v0.2.11-rc1. No path/option/control input.
TAG_RE = re.compile(r"skillctl/v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z]+(?:[.-][0-9A-Za-z]+)*)?\Z", re.ASCII)


class VerificationError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise VerificationError(message)


def strict_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(VerificationError("nonfinite JSON")))


def run(args):
    # External verifier diagnostics are retained on stderr; stdout is data only.
    kwargs = {}
    if args[:3] == ["gh", "release", "download"]:
        # Bound actual download writes even if remote metadata changes mid-read.
        def limit_download():
            resource.setrlimit(resource.RLIMIT_FSIZE, (MAX_BINARY, MAX_BINARY))
        kwargs["preexec_fn"] = limit_download
    return subprocess.run(args, check=True, stdout=subprocess.PIPE, **kwargs).stdout


def api(endpoint):
    return strict_json(run(["gh", "api", f"repos/{REPO}/{endpoint}"]))


def tag_commit(tag):
    obj = api("git/ref/tags/" + quote(tag, safe=""))["object"]
    for _ in range(8):
        sha = obj["sha"]
        require(isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha), "invalid tag SHA")
        if obj["type"] == "commit":
            return sha
        require(obj["type"] == "tag", "tag does not resolve to commit")
        obj = api("git/tags/" + sha)["object"]
    raise VerificationError("tag chain too deep")


def file_sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def check_manifest(stage):
    raw = (stage / "SHA256SUMS").read_bytes()
    lines = raw.splitlines(keepends=True)
    require(len(lines) == len(BINARIES), "manifest must contain exactly five binaries")
    seen = set()
    for line in lines:
        match = re.fullmatch(rb"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)\n", line)
        require(match is not None, "unsupported checksum line format")
        digest, name = match.groups()
        name = name.decode("ascii")
        require(name in BINARIES and name not in seen, "unexpected or duplicate manifest name")
        seen.add(name)
        path = stage / name
        require(path.is_file() and not path.is_symlink(), "binary must be a regular file")
        require(file_sha256(path) == digest.decode(), "binary checksum mismatch")
    require(seen == set(BINARIES), "incomplete manifest")
    return raw


def check_statement(raw, tag, sha, subjects):
    # Only consume --print-provenance stdout AFTER successful cryptographic verification.
    statement = strict_json(raw)
    require(statement["_type"] == "https://in-toto.io/Statement/v0.1", "unsupported statement")
    require(statement["predicateType"] == "https://slsa.dev/provenance/v0.2", "unsupported provenance")
    actual_subjects = {}
    for subject in statement["subject"]:
        name = subject["name"]
        require(name not in actual_subjects, "duplicate provenance subject")
        actual_subjects[name] = subject["digest"]
    require(actual_subjects == subjects, "provenance subject names/digests mismatch")
    predicate = statement["predicate"]
    require(predicate["builder"]["id"] == BUILDER, "builder mismatch")
    invocation = predicate["invocation"]
    source = invocation["configSource"]
    require(source["digest"]["sha1"] == sha, "provenance source SHA mismatch")
    require(source["entryPoint"] == WORKFLOW, "provenance workflow mismatch")
    # source URI spelling is controlled by the generator/verifier; --source-uri
    # and --source-tag enforce repository/tag. Bind the signed environment too.
    environment = invocation["environment"]
    require(environment["github_sha1"] == sha, "provenance environment SHA mismatch")
    require(environment["github_ref"] == "refs/tags/" + tag, "provenance ref mismatch")


def verify_ci(stage, tag, sha, provenance):
    manifest = check_manifest(stage)
    run(["cosign", "verify-blob", str(stage / "SHA256SUMS"),
         "--bundle", str(stage / "SHA256SUMS.cosign.bundle"),
         "--certificate-identity", f"https://github.com/{REPO}/{WORKFLOW}@refs/tags/{tag}",
         "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com"])
    subjects = {name: {"sha256": file_sha256(stage / name)}
                for name in BINARIES}
    for name in BINARIES:
        statement = run(["slsa-verifier", "verify-artifact", str(stage / name),
                         "--provenance-path", str(stage / provenance),
                         "--source-uri", "git+https://github.com/" + REPO,
                         "--source-tag", tag, "--builder-id", BUILDER, "--print-provenance"])
        check_statement(statement, tag, sha, subjects)
    require(check_manifest(stage) == manifest, "manifest changed during verification")
    return manifest


def pinned_public_key(root):
    public = root / "INFRA/skillctl-release.pub"
    der = run(["openssl", "pkey", "-pubin", "-in", str(public), "-outform", "DER"])
    require(der[:12] == bytes.fromhex("302a300506032b6570032100") and len(der) == 44,
            "expected Ed25519 public key")
    require(hashlib.sha256(der[12:]).hexdigest() == PUBLIC_FP, "release public key pin mismatch")
    return public.read_bytes()


def prepare(tag, root):
    require(isinstance(tag, str) and TAG_RE.fullmatch(tag) is not None, "invalid release tag")
    for tool in ("gh", "cosign", "slsa-verifier", "openssl"):
        require(shutil.which(tool) is not None, "required tool missing: " + tool)
    out = root / "release" / tag
    # Refuse symlinked/existing outputs rather than mixing verified and local assets.
    require(not out.exists() and not out.is_symlink(), "release output already exists")
    for parent in (root / "release", root / "release/skillctl"):
        require(not parent.is_symlink(), "release output parent is a symlink")
    public = pinned_public_key(root)
    sha = tag_commit(tag)
    release = api("releases/tags/" + quote(tag, safe=""))
    require(release["tag_name"] == tag, "release tag mismatch")
    names = [asset["name"] for asset in release["assets"]]
    require(len(names) == len(set(names)), "duplicate release assets")
    provenances = [name for name in names if re.fullmatch(r"[A-Za-z0-9_.-]+\.intoto\.jsonl", name)]
    require(len(provenances) == 1, "expected one SLSA provenance asset")
    provenance = provenances[0]
    required = (*BINARIES, "SHA256SUMS", "SHA256SUMS.cosign.bundle", provenance)
    require(set(required).issubset(names), "required CI release asset missing")
    sizes = {}
    for asset in release["assets"]:
        name = asset["name"]
        if name not in required:
            continue
        size = asset["size"]
        bound = MAX_BINARY if name in BINARIES else MAX_METADATA
        require(type(size) is int and 0 < size <= bound, "release asset exceeds size policy")
        sizes[name] = size
    require(sum(sizes.values()) <= MAX_TOTAL, "release exceeds total size policy")
    with tempfile.TemporaryDirectory(prefix="skillctl-fallback-") as temp:
        stage = Path(temp)
        args = ["gh", "release", "download", tag, "--repo", REPO, "--dir", str(stage)]
        for name in required:
            args.extend(["--pattern", name])
        run(args)
        for name in required:
            path = stage / name
            require(path.is_file() and not path.is_symlink(), "nonregular CI asset")
            require(path.stat().st_size == sizes[name], "downloaded asset size differs from metadata")
        manifest = verify_ci(stage, tag, sha, provenance)
        require(tag_commit(tag) == sha, "tag moved during verification")
        # Pin the public bytes already checked; never derive the verify anchor
        # from the private signing key or trust a release-supplied public key.
        (stage / "skillctl-release.pub").write_bytes(public)
        key = os.environ.get("RELEASE_KEY", str(Path.home() / ".config/m3c/skill-release.key"))
        run(["openssl", "pkeyutl", "-sign", "-inkey", key, "-rawin", "-in",
             str(stage / "SHA256SUMS"), "-out", str(stage / "SHA256SUMS.sig")])
        run(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", str(stage / "skillctl-release.pub"),
             "-rawin", "-in", str(stage / "SHA256SUMS"), "-sigfile", str(stage / "SHA256SUMS.sig")])
        require((stage / "SHA256SUMS").read_bytes() == manifest, "signed manifest bytes changed")
        out.parent.mkdir(parents=True, exist_ok=True)
        out.mkdir(mode=0o700)  # exclusive: never overwrite an earlier release
        try:
            for name in (*required, "SHA256SUMS.sig", "skillctl-release.pub"):
                shutil.copyfile(stage / name, out / name)
        except BaseException:
            # Only this invocation's exclusively created output may be removed.
            shutil.rmtree(out)
            raise
    print(f"Local verified-CI fallback signature prepared: {out}")
    print("No upload or publication performed. This is not customer release approval.")


def main(argv):
    try:
        require(len(argv) == 1, "usage: skillctl-release.sh skillctl/v<semver>")
        prepare(argv[0], Path(__file__).resolve().parent.parent)
        return 0
    except (VerificationError, OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
        print(f"Fallback signing refused: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
