# GitLab Enterprise Deployment Runbook

This runbook guides enterprise platform teams and administrators through deploying, mirroring, and managing `m3c-tools` and `skillctl` within an internal or customer GitLab instance (such as `Master2 192.168.0.135`).

---

## 1. Repository Setup & Mirroring

### 1.1 Initial Import / Push to GitLab

To import this repository into your GitLab instance:

1. Create a new project in GitLab (e.g. `ai-platform/m3c-tools` on `192.168.0.135`).
2. Add your GitLab instance as a remote and push the codebase:
   ```bash
   # Add remote
   git remote add gitlab-local git@192.168.0.135:ai-platform/m3c-tools.git

   # Push master branch and tags
   git push gitlab-local master --tags
   ```

Or use the automated synchronization script:
```bash
make gitlab-sync GITLAB_URL="git@192.168.0.135:ai-platform/m3c-tools.git"
```

### 1.2 Automated Repository Mirroring (Optional)

If maintaining a continuous mirror from GitHub:
1. In GitLab, navigate to **Settings → Repository → Mirroring repositories**.
2. Set **Git repository URL** to `https://github.com/kamir/m3c-tools.git` (or SSH equivalent).
3. Select **Mirror direction: Pull**.
4. Configure authentication via Deploy Key or Personal Access Token.

---

## 2. GitLab CI/CD Pipeline

The repository includes a ready-to-run [`.gitlab-ci.yml`](../.gitlab-ci.yml) designed for standard GitLab Runners.

### 2.1 Stages & Execution

| Stage | Job | Description |
|---|---|---|
| `lint` | `lint-and-vet` | Runs `go vet` and `golangci-lint` for static code analysis. |
| `test` | `unit-tests` | Runs all offline unit tests under race detection (`-race`). |
| `build` | `build-binaries` | Cross-compiles pure Go binaries for Linux (amd64/arm64), macOS (amd64/arm64), and Windows (amd64), and computes `SHA256SUMS`. |
| `release` | `gitlab-release` | Triggered on tags (`v*` or `skillctl/v*`), uploads binaries to GitLab Generic Package Registry and cuts a GitLab Release with asset links. |

### 2.2 Runner Requirements

- **Runner Type**: Docker Executor (recommended) or Shell Executor.
- **Docker Image**: `golang:1.26-bookworm` (default in pipeline).
- **Network Access**: Internal access to the GitLab API for package uploads.

---

## 3. Package Registry & Binary Distribution

When a tag is pushed (e.g., `git tag v2.10.1 && git push gitlab-local v2.10.1`), the CI pipeline automatically uploads all compiled binaries to the **GitLab Generic Package Registry**:

```
${GITLAB_URL}/api/v4/projects/${PROJECT_ID}/packages/generic/m3c-tools/${TAG}/
```

### 3.1 Client Installation One-Liner

Enterprise developers and agents can install `skillctl` or `m3c-tools` directly from your internal GitLab instance using [`tools/gitlab-install.sh`](../tools/gitlab-install.sh):

```bash
curl -fsSL http://192.168.0.135/ai-platform/m3c-tools/-/raw/main/tools/gitlab-install.sh | \
  GITLAB_URL="http://192.168.0.135" \
  PROJECT_PATH="ai-platform/m3c-tools" \
  TOOL="skillctl" \
  bash
```

If the project is private, pass a GitLab Personal Access Token:
```bash
curl -fsSL ... | GITLAB_TOKEN="glpat-xxxxxxxxxxxx" bash
```

---

## 4. Air-Gapped / Isolated Network Operations

For strictly air-gapped enterprise environments with zero outbound internet access:

1. **Pre-cache Go Dependencies**:
   - The repository uses Go modules vendor caching or GitLab CI caching (`.go/pkg/mod/`).
   - Run `go mod vendor` if you prefer checking in dependencies for complete zero-network builds.
2. **Offline Skill Verification**:
   - `skillctl` verification requires **no internet connection** or hosted Certificate Authority.
   - Pinned root public keys (`INFRA/skillctl-release.pub` or enterprise custom keys) verify signatures and revocation lists offline.
3. **Local Docker Registry**:
   - For `thinking-engine`, build and tag images into your internal GitLab Container Registry:
     ```bash
     docker build -f deploy/thinking-engine/Dockerfile -t 192.168.0.135:5050/ai-platform/m3c-tools/thinking-engine:v1.0.0 .
     docker push 192.168.0.135:5050/ai-platform/m3c-tools/thinking-engine:v1.0.0
     ```

---

## 5. Security & RBAC Best Practices

- **Protect Release Branches & Tags**:
  In GitLab under **Settings → Repository → Protected branches / Protected tags**, restrict `master` and `v*` tags so only Maintainers can trigger releases.
- **Rotate CI Job Tokens**:
  Ensure the Generic Package Registry upload uses the ephemeral `${CI_JOB_TOKEN}` provided automatically by GitLab CI.
- **Audit Logs**:
  Review GitLab audit events for package downloads, tag creations, and runner activity.
