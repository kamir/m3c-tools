#!/usr/bin/env python3
"""Collect commit-bound release gates from trusted master-push workflow runs.

This checks execution provenance, not just check names. API calls are injectable
for offline tests. Missing/ambiguous/failed evidence writes a negative record and
returns nonzero. This collector does not authorize publication by itself.
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlencode


ACTION_APP = 15368
MASTER = "master"
POLICY = {
    "id": "m3c.release-ci-evidence.master-push.v2",
    "gosec_decision": "Authenticated latest master-push gosec-diff-gate no-new-findings relative to the committed signature baseline.",
    "sarif_decision": "Separate ingestion health only; never a vulnerability or no-new-findings decision.",
    "ghas_pr_decision": "Not collected on master; GHAS PR check remains an independent merge requirement. Missing checks or empty alert lists are never inferred as clean.",
    "assurance_limit": "Existing baseline findings remain backlog and require separate review. Collection is not a vulnerability-free or customer-enterprise acceptance claim.",
}
GATES = {
    "unit-tests": (("ci.yml", "Unit Tests"),),
    "e2e": (("ci.yml", "Unit Tests"),),
    "race": (("ci.yml", "skillctl Security Tests (-race)"),),
    "lint": (("ci.yml", "Lint & Vet"),),
    "gosec-sast": (
        ("gosec-diff-gate.yml", "gosec no-new-findings (in-CI diff gate)"),
        ("gosec.yml", "gosec SAST (SARIF -> Code Scanning)"),
    ),
    "govulncheck-cve": (("ci.yml", "govulncheck (reachable CVEs)"),),
    "gitleaks-secret": (("ci.yml", "gitleaks (secret scan)"),),
}


class EvidenceError(Exception):
    """An expected execution cannot be authenticated or did not pass."""


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def positive_id(value, label):
    require(type(value) is int and value > 0, f"invalid {label}")
    return value


def gh_api(endpoint):
    """Only read GitHub metadata; never include credentials in error reports."""
    try:
        result = subprocess.run(
            ["gh", "api", "--method", "GET", endpoint],
            check=False, capture_output=True, text=True, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise EvidenceError(f"GitHub API unavailable for {endpoint}") from exc
    require(result.returncode == 0, f"GitHub API request failed for {endpoint}")
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise EvidenceError(f"invalid GitHub API JSON for {endpoint}") from exc


class Collector:
    def __init__(self, repo, commit, api=gh_api):
        require(bool(re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo)), "invalid repository")
        require(bool(re.fullmatch(r"[0-9a-f]{40}", commit)), "commit must be a full lowercase SHA")
        self.repo, self.commit, self.api = repo, commit, api
        self.prefix = f"repos/{repo}"
        self.workflows = {}
        self.job_evidence = {}
        self.audit = {
            "schema": "m3c.release-check-provenance.v1", "repository": repo,
            "policy": dict(POLICY),
            "commit": commit, "source_event": "push", "source_branch": MASTER,
            "workflows": {}, "checks": [], "gates": {}, "errors": [],
        }

    def request(self, endpoint):
        try:
            result = self.api(endpoint)
        except EvidenceError:
            raise
        except Exception as exc:
            raise EvidenceError(f"GitHub API failed for {endpoint}") from exc
        require(isinstance(result, dict), f"invalid API object for {endpoint}")
        return result

    def items(self, endpoint, key):
        """Read all pages, detecting truncation instead of trusting page one."""
        result = []
        separator = "&" if "?" in endpoint else "?"
        for page in range(1, 101):
            data = self.request(f"{endpoint}{separator}per_page=100&page={page}")
            batch, total = data.get(key), data.get("total_count")
            require(isinstance(batch, list), f"invalid {key} collection")
            require(all(isinstance(item, dict) for item in batch), f"invalid {key} collection item")
            require(type(total) is int and total >= 0, f"invalid {key} count")
            result.extend(batch)
            if len(result) >= total:
                require(len(result) == total, f"{key} collection changed while reading")
                return result
            require(len(batch) > 0, f"truncated {key} collection")
        raise EvidenceError(f"{key} collection exceeds pagination limit")

    def validate_run(self, run, workflow_id, filename):
        require(isinstance(run.get("repository"), dict) and isinstance(run.get("head_repository"), dict),
                "missing run repository identity")
        require(run.get("repository", {}).get("full_name") == self.repo, "wrong run repository")
        require(run.get("head_repository", {}).get("full_name") == self.repo, "wrong source repository")
        require(run.get("head_sha") == self.commit, "wrong source commit")
        require(run.get("event") == "push" and run.get("head_branch") == MASTER,
                "run is not a master push")
        require(run.get("workflow_id") == workflow_id, "wrong workflow ID")
        require(run.get("path") == f".github/workflows/{filename}", "wrong workflow path")
        for key in ("id", "run_number", "run_attempt", "check_suite_id"):
            positive_id(run.get(key), key)

    def workflow(self, filename):
        if filename in self.workflows:
            value = self.workflows[filename]
            if isinstance(value, EvidenceError):
                raise value
            return value
        try:
            metadata = self.request(f"{self.prefix}/actions/workflows/{filename}")
            workflow_id = positive_id(metadata.get("id"), "workflow ID")
            require(metadata.get("path") == f".github/workflows/{filename}", "wrong registered workflow path")
            require(metadata.get("state") == "active", "workflow is not active")
            run = self.latest_run(filename, workflow_id)
            self.audit["workflows"][filename] = self.run_record(run)
            require(run.get("status") == "completed" and run.get("conclusion") == "success",
                    f"latest {filename} run/attempt is not completed successfully")
            jobs = self.items(
                f"{self.prefix}/actions/runs/{run['id']}/attempts/{run['run_attempt']}/jobs", "jobs",
            )
            require(len({j.get("id") for j in jobs}) == len(jobs), "duplicate job IDs")
            value = (run, jobs)
        except EvidenceError as exc:
            self.workflows[filename] = exc
            raise
        self.workflows[filename] = value
        return value

    def latest_run(self, filename, workflow_id):
        query = urlencode({"event": "push", "branch": MASTER, "head_sha": self.commit})
        runs = self.items(f"{self.prefix}/actions/workflows/{workflow_id}/runs?{query}", "workflow_runs")
        require(bool(runs), f"no master-push run for {filename} at {self.commit}")
        # Do not discard an invalid producer and fall back to an older green.
        for run in runs:
            self.validate_run(run, workflow_id, filename)
        latest = max(runs, key=lambda r: (r["run_number"], r["id"]))
        require(sum(r["run_number"] == latest["run_number"] for r in runs) == 1,
                "ambiguous latest workflow run")
        run = self.request(f"{self.prefix}/actions/runs/{latest['id']}")
        self.validate_run(run, workflow_id, filename)
        require(run["id"] == latest["id"] and run["run_number"] == latest["run_number"], "run identity changed")
        require(run["run_attempt"] >= latest["run_attempt"], "run attempt moved backwards")
        return run

    def run_record(self, run):
        return {
            key: run.get(key) for key in (
                "id", "workflow_id", "path", "head_sha", "event", "head_branch",
                "run_number", "run_attempt", "check_suite_id", "status", "conclusion",
                "created_at", "updated_at", "html_url",
            )
        }

    def job(self, filename, name):
        key = (filename, name)
        if key in self.job_evidence:
            return self.job_evidence[key]
        run, jobs = self.workflow(filename)
        matches = [job for job in jobs if job.get("name") == name]
        require(len(matches) == 1, f"missing or duplicate job {name!r} in {filename}")
        job = matches[0]
        positive_id(job.get("id"), "job ID")
        require(job.get("run_id") == run["id"] and job.get("run_attempt") == run["run_attempt"],
                f"wrong run/attempt for job {name!r}")
        require(job.get("head_sha") == self.commit, f"wrong job commit for {name!r}")
        require(job.get("status") == "completed" and job.get("conclusion") == "success",
                f"job {name!r} is not completed successfully")
        url = job.get("check_run_url", "")
        pattern = rf"https://api\.github\.com/repos/{re.escape(self.repo)}/check-runs/([0-9]+)"
        match = re.fullmatch(pattern, url)
        require(match is not None, f"invalid job check-run URL for {name!r}")
        check_id = int(match.group(1))
        check = self.request(f"{self.prefix}/check-runs/{check_id}")
        require(isinstance(check.get("app"), dict) and isinstance(check.get("check_suite"), dict),
                "missing job check producer or suite")
        self.audit["checks"].append({
            "id": check.get("id"), "name": check.get("name"),
            "app_id": check["app"].get("id"), "check_suite_id": check["check_suite"].get("id"),
            "head_sha": check.get("head_sha"), "status": check.get("status"),
            "conclusion": check.get("conclusion"), "run_id": run["id"],
            "run_attempt": run["run_attempt"], "job_id": job["id"],
        })
        require(check.get("id") == check_id and check.get("name") == name, "wrong job check identity")
        require(check.get("app", {}).get("id") == ACTION_APP, "wrong job check app")
        require(check.get("head_sha") == self.commit, "wrong job check commit")
        require(check.get("check_suite", {}).get("id") == run["check_suite_id"], "wrong job check suite")
        require(check.get("status") == "completed" and check.get("conclusion") == "success",
                "job check is not completed successfully")
        evidence = {
            "workflow": filename, "workflow_id": run["workflow_id"], "run_id": run["id"],
            "run_attempt": run["run_attempt"], "job_id": job["id"], "check_run_id": check_id,
            "check_suite_id": run["check_suite_id"], "app_id": ACTION_APP,
            "head_sha": self.commit, "status": "completed", "conclusion": "success",
            "url": f"https://github.com/{self.repo}/actions/runs/{run['id']}/job/{job['id']}",
            "attempt_url": f"https://github.com/{self.repo}/actions/runs/{run['id']}/attempts/{run['run_attempt']}",
        }
        self.job_evidence[key] = evidence
        return evidence

    def collect(self):
        output = []
        for gate, requirements in GATES.items():
            try:
                evidence = [self.job(filename, name) for filename, name in requirements]
                self.audit["gates"][gate] = {"status": "pass", "evidence": evidence}
                note = "Verified exact master-push workflow and latest run/attempt/job/check producer; audit records every identity."
                if gate == "gosec-sast":
                    note = ("No new findings relative to the reviewed committed baseline; SARIF is ingestion health only. "
                            "GHAS PR check remains a separate merge requirement. Not vulnerability-free or customer acceptance.")
                output.append({"id": gate, "status": "pass", "evidence": evidence[0]["url"],
                               "note": note})
            except EvidenceError as exc:
                message = str(exc)
                self.audit["errors"].append({"gate": gate, "error": message})
                self.audit["gates"][gate] = {"status": "fail", "error": message}
                output.append({"id": gate, "status": "fail", "evidence": "", "note": message})
        # Reselect the latest run, not merely the old run's latest attempt: a
        # different workflow run may have started while jobs were inspected.
        self.audit["final_workflows"] = {}
        for filename, value in self.workflows.items():
            if isinstance(value, EvidenceError):
                continue
            run, _ = value
            try:
                current = self.latest_run(filename, run["workflow_id"])
                self.audit["final_workflows"][filename] = self.run_record(current)
                require(current["id"] == run["id"] and current["run_attempt"] == run["run_attempt"]
                        and current.get("status") == "completed"
                        and current.get("conclusion") == "success", "source attempt changed during collection")
            except EvidenceError as exc:
                for record in output:
                    if any(w == filename for w, _ in GATES[record["id"]]):
                        record.update(status="fail", evidence="", note=str(exc))
                        self.audit["gates"][record["id"]].update(status="fail", error=str(exc))
                        self.audit["errors"].append({"gate": record["id"], "error": str(exc)})
        self.audit["success"] = all(g["status"] == "pass" for g in output)
        return output, self.audit


def main(argv=None, api=gh_api):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--output", required=True, help="gate-input JSON array (also written on negative decisions)")
    parser.add_argument("--audit-output", help="execution provenance and errors JSON")
    args = parser.parse_args(argv)
    try:
        collector = Collector(args.repo, args.commit, api)
        gates, audit = collector.collect()
    except EvidenceError as exc:
        gates = [{"id": gate, "status": "fail", "evidence": "", "note": str(exc)} for gate in GATES]
        audit = {"schema": "m3c.release-check-provenance.v1", "policy": dict(POLICY),
                 "success": False, "errors": [{"error": str(exc)}]}
    try:
        Path(args.output).write_text(json.dumps(gates, indent=2) + "\n", encoding="utf-8")
        if args.audit_output:
            Path(args.audit_output).write_text(json.dumps(audit, indent=2) + "\n", encoding="utf-8")
    except OSError:
        print("release-check collector could not retain its evidence files", file=sys.stderr)
        return 2
    if not audit["success"]:
        print("release-check collection FAILED; negative evidence retained", file=sys.stderr)
        return 1
    print("release-check collection passed for the exact source commit", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
