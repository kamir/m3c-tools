#!/usr/bin/env python3
"""Offline adversarial contracts for the release-check collector."""

import contextlib
import copy
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


SPEC = importlib.util.spec_from_file_location(
    "collector", Path(__file__).with_name("collect-release-checks.py"),
)
collector = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(collector)
REPO = "example/tools"
SHA = "a" * 40


class FakeAPI:
    def __init__(self):
        self.calls = []
        self.metadata, self.runs, self.jobs, self.checks = {}, {}, {}, {}
        for n, filename in enumerate(("ci.yml", "gosec-diff-gate.yml", "gosec.yml"), 1):
            self.metadata[filename] = {"id": n, "path": f".github/workflows/{filename}", "state": "active"}
            run = {
                "id": n * 100, "workflow_id": n, "run_number": 1, "run_attempt": 2,
                "repository": {"full_name": REPO}, "head_repository": {"full_name": REPO},
                "head_sha": SHA, "head_branch": "master", "event": "push",
                "path": f".github/workflows/{filename}", "check_suite_id": n * 1000,
                "status": "completed", "conclusion": "success",
            }
            self.runs[n] = [run]
            names = sorted({name for requirements in collector.GATES.values()
                            for workflow, name in requirements if workflow == filename})
            self.jobs[run["id"]] = []
            for index, name in enumerate(names, 1):
                job_id = n * 10000 + index
                check_id = job_id + 100000
                self.jobs[run["id"]].append({
                    "id": job_id, "name": name, "run_id": run["id"], "run_attempt": 2,
                    "head_sha": SHA, "status": "completed", "conclusion": "success",
                    "check_run_url": f"https://api.github.com/repos/{REPO}/check-runs/{check_id}",
                })
                self.checks[check_id] = {
                    "id": check_id, "name": name, "app": {"id": collector.ACTION_APP},
                    "head_sha": SHA, "check_suite": {"id": run["check_suite_id"]},
                    "status": "completed", "conclusion": "success",
                }

    def __call__(self, endpoint):
        self.calls.append(endpoint)
        parsed = urlsplit(endpoint)
        path, query = parsed.path, parse_qs(parsed.query)
        prefix = f"repos/{REPO}"
        if path.startswith(f"{prefix}/actions/workflows/"):
            suffix = path.removeprefix(f"{prefix}/actions/workflows/")
            if suffix.endswith("/runs"):
                self.assert_query(query, "event", "push")
                self.assert_query(query, "branch", "master")
                self.assert_query(query, "head_sha", SHA)
                return self.page(self.runs[int(suffix.split('/')[0])], "workflow_runs", query)
            return copy.deepcopy(self.metadata[suffix])
        if path.startswith(f"{prefix}/actions/runs/"):
            suffix = path.removeprefix(f"{prefix}/actions/runs/")
            run_id = int(suffix.split("/")[0])
            if "/attempts/" in suffix:
                if "/attempts/2/jobs" not in suffix:
                    raise AssertionError("collector did not use the latest attempt-specific jobs endpoint")
                return self.page(self.jobs[run_id], "jobs", query)
            return copy.deepcopy(next(run for runs in self.runs.values() for run in runs if run["id"] == run_id))
        if path.startswith(f"{prefix}/check-runs/"):
            return copy.deepcopy(self.checks[int(path.rsplit("/", 1)[-1])])
        if path == f"{prefix}/commits/{SHA}/check-runs":
            raise AssertionError("PR-only GHAS decisions cannot authorize master collection")
        raise AssertionError(f"unexpected API read {endpoint}")

    @staticmethod
    def assert_query(query, key, expected):
        if query.get(key) != [expected]:
            raise AssertionError(f"wrong {key} API filter")

    @staticmethod
    def page(rows, key, query):
        start = (int(query.get("page", [1])[0]) - 1) * 100
        return {"total_count": len(rows), key: copy.deepcopy(rows[start:start + 100])}


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.api = FakeAPI()

    def collect(self, api=None):
        return collector.Collector(REPO, SHA, api or self.api).collect()

    def assert_failed(self, gate, api=None):
        gates, audit = self.collect(api)
        record = next(g for g in gates if g["id"] == gate)
        self.assertEqual(record["status"], "fail")
        self.assertFalse(audit["success"])
        self.assertTrue(audit["errors"])
        return record

    def test_success_records_run_attempt_job_app_and_commit(self):
        gates, audit = self.collect()
        self.assertTrue(audit["success"])
        self.assertEqual(len(gates), 7)
        self.assertEqual(len(audit["gates"]["gosec-sast"]["evidence"]), 2)
        for gate in gates:
            self.assertEqual(gate["status"], "pass")
        proof = audit["gates"]["unit-tests"]["evidence"][0]
        self.assertEqual((proof["run_attempt"], proof["app_id"], proof["head_sha"]), (2, 15368, SHA))
        self.assertIn("/attempts/2", proof["attempt_url"])
        self.assertIn("/job/", proof["url"])

    def test_new_failed_or_running_run_never_falls_back_to_old_success(self):
        for status, conclusion in (("completed", "failure"), ("in_progress", None)):
            with self.subTest(status=status):
                self.setUp()
                newer = dict(self.api.runs[1][0], id=101, run_number=2, status=status, conclusion=conclusion)
                self.api.runs[1].append(newer)
                self.assert_failed("unit-tests")

    def test_wrong_run_producer_commit_event_branch_and_workflow_fail(self):
        alterations = (
            {"repository": {"full_name": "attacker/tools"}},
            {"head_repository": {"full_name": "attacker/tools"}},
            {"head_sha": "b" * 40}, {"event": "pull_request"},
            {"head_branch": "feature"}, {"workflow_id": 900},
            {"path": ".github/workflows/spoof.yml"},
        )
        for alteration in alterations:
            with self.subTest(alteration=alteration):
                self.setUp()
                self.api.runs[1][0].update(alteration)
                self.assert_failed("unit-tests")

    def test_wrong_registered_workflow_is_not_accepted(self):
        self.api.metadata["ci.yml"]["path"] = ".github/workflows/spoof.yml"
        self.assert_failed("unit-tests")

    def test_missing_and_duplicate_job_names_fail(self):
        for duplicate in (False, True):
            with self.subTest(duplicate=duplicate):
                self.setUp()
                target = next(j for j in self.api.jobs[100] if j["name"] == "Unit Tests")
                if duplicate:
                    self.api.jobs[100].append(dict(target, id=999))
                else:
                    self.api.jobs[100].remove(target)
                self.assert_failed("unit-tests")

    def test_prior_attempt_job_wrong_sha_and_wrong_run_fail(self):
        for alteration in ({"run_attempt": 1}, {"head_sha": "b" * 40}, {"run_id": 999}):
            with self.subTest(alteration=alteration):
                self.setUp()
                next(j for j in self.api.jobs[100] if j["name"] == "Unit Tests").update(alteration)
                self.assert_failed("unit-tests")

    def test_job_check_wrong_app_suite_commit_or_result_fail(self):
        alterations = (
            {"app": {"id": 1}}, {"check_suite": {"id": 999}},
            {"head_sha": "b" * 40}, {"status": "in_progress", "conclusion": None},
            {"conclusion": "neutral"}, {"name": "spoof"},
        )
        for alteration in alterations:
            with self.subTest(alteration=alteration):
                self.setUp()
                job = next(j for j in self.api.jobs[100] if j["name"] == "Unit Tests")
                check_id = int(job["check_run_url"].rsplit("/", 1)[-1])
                self.api.checks[check_id].update(alteration)
                self.assert_failed("unit-tests")

    def test_check_run_url_cannot_select_other_repo_or_host(self):
        for url in ("https://attacker.invalid/check-runs/1", "https://api.github.com/repos/evil/tools/check-runs/1"):
            with self.subTest(url=url):
                self.setUp()
                next(j for j in self.api.jobs[100] if j["name"] == "Unit Tests")["check_run_url"] = url
                self.assert_failed("unit-tests")

    def test_sarif_alone_or_missing_failed_components_cannot_pass(self):
        for source in ("diff_missing", "diff_failed", "sarif_failed"):
            with self.subTest(source=source):
                self.setUp()
                if source == "diff_missing":
                    self.api.runs[2] = []
                elif source == "diff_failed":
                    self.api.runs[2][0]["conclusion"] = "failure"
                else:
                    self.api.runs[3][0]["conclusion"] = "failure"
                self.assert_failed("gosec-sast")

    def test_policy_never_uses_empty_ghas_alerts_as_security_evidence(self):
        gates, audit = self.collect()
        self.assertTrue(audit["success"])
        self.assertEqual(audit["policy"]["id"], "m3c.release-ci-evidence.master-push.v2")
        self.assertFalse(any("/commits/" in path or "/code-scanning/" in path for path in self.api.calls))
        self.assertEqual(len(audit["gates"]["gosec-sast"]["evidence"]), 2)
        note = next(g["note"] for g in gates if g["id"] == "gosec-sast")
        self.assertIn("SARIF is ingestion health only", note)
        self.assertIn("separate merge requirement", note)

    def test_malformed_api_metadata_is_a_negative_decision(self):
        for field in ("app", "check_suite"):
            with self.subTest(field=field):
                self.setUp()
                job = next(j for j in self.api.jobs[100] if j["name"] == "Unit Tests")
                check_id = int(job["check_run_url"].rsplit("/", 1)[-1])
                self.api.checks[check_id][field] = None
                self.assert_failed("unit-tests")

    def test_invalid_cli_commit_retains_negative_decision(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "gates.json"
            with contextlib.redirect_stderr(io.StringIO()):
                code = collector.main(["--repo", REPO, "--commit", "not-a-sha", "--output", str(output)], api=self.api)
            self.assertEqual(code, 1)
            self.assertTrue(all(g["status"] == "fail" for g in json.loads(output.read_text())))

    def test_missing_workflow_and_api_outage_retain_negative_evidence(self):
        self.api.runs[1] = []
        self.assert_failed("unit-tests")
        def unavailable(_):
            raise OSError("synthetic outage")
        self.assert_failed("unit-tests", unavailable)

    def test_new_attempt_started_during_collection_invalidates_success(self):
        original = self.api
        counts = {}
        def rerun(endpoint):
            result = original(endpoint)
            if endpoint.endswith("/actions/runs/100"):
                counts[endpoint] = counts.get(endpoint, 0) + 1
                if counts[endpoint] > 1:
                    result.update(run_attempt=3, status="in_progress", conclusion=None)
            return result
        self.assert_failed("unit-tests", rerun)

    def test_new_run_created_during_collection_invalidates_old_success(self):
        for workflow_id, gate in ((1, "unit-tests"), (2, "gosec-sast"), (3, "gosec-sast")):
            with self.subTest(workflow_id=workflow_id):
                self.setUp()
                original = self.api
                listings = 0
                def new_run(endpoint):
                    nonlocal listings
                    if f"/actions/workflows/{workflow_id}/runs?" in endpoint:
                        listings += 1
                        if listings == 2:
                            latest = dict(original.runs[workflow_id][0], id=workflow_id * 100 + 1,
                                          run_number=2, status="in_progress", conclusion=None)
                            original.runs[workflow_id].append(latest)
                    return original(endpoint)
                result = self.assert_failed(gate, new_run)
                self.assertIn("changed during collection", result["note"])

    def test_pagination_does_not_hide_a_later_failed_run(self):
        old = self.api.runs[1][0]
        self.api.runs[1] = [dict(old, id=1000 + i, run_number=10 + i) for i in range(101)]
        self.api.runs[1][-1]["conclusion"] = "failure"
        self.assert_failed("unit-tests")
        self.assertTrue(any("page=2" in call for call in self.api.calls))

    def test_cli_writes_failures_and_audit_before_returning_nonzero(self):
        self.api.runs[2][0]["conclusion"] = "failure"
        with tempfile.TemporaryDirectory() as directory:
            output, audit = Path(directory) / "gates.json", Path(directory) / "audit.json"
            with contextlib.redirect_stderr(io.StringIO()):
                code = collector.main(["--repo", REPO, "--commit", SHA, "--output", str(output),
                                       "--audit-output", str(audit)], api=self.api)
            self.assertEqual(code, 1)
            self.assertFalse(json.loads(audit.read_text())["success"])
            self.assertTrue(any(g["status"] == "fail" for g in json.loads(output.read_text())))

    def test_cli_output_matches_release_evidence_gate_input_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "gates.json"
            audit = Path(directory) / "audit.json"
            with contextlib.redirect_stderr(io.StringIO()):
                code = collector.main(["--repo", REPO, "--commit", SHA, "--output", str(output),
                                       "--audit-output", str(audit)], api=self.api)
            self.assertEqual(code, 0)
            records = json.loads(output.read_text())
            proof = json.loads(audit.read_text())
            for record in records:
                self.assertEqual(set(record), {"id", "status", "evidence", "note"})
                expected = proof["gates"][record["id"]]["evidence"][0]["url"]
                self.assertEqual(record["evidence"], expected)
                self.assertTrue(record["evidence"].startswith(f"https://github.com/{REPO}/actions/runs/"))


if __name__ == "__main__":
    unittest.main()
