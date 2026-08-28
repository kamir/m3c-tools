# Local git-forge test environments (SPEC-0356)

Two disposable forges for testing the skillctl **git artifact backend**
(`pkg/skillctl/backend/git`). The backend is provider-neutral, so the same code
drives both; pick by what you're testing.

| | Gitea | GitLab CE |
|---|---|---|
| Use for | inner loop / CI (git-carrier + generic REST) | GitLab-API acceptance (Deploy-Token, `commits actions[]`, package registry, protected tags) |
| Image / RAM | ~150 MB / <512 MB | ~3 GB / ~2.5-3 GB |
| First boot | ~10 s | ~3-5 min |
| URL | http://localhost:3000 | http://localhost:8929 |

The unit tests in `git_test.go` need **neither** — they run against a local
`git init --bare` repo. These forges are for the **integration** layer (auth +
remote push over HTTP, and the GitLab-specific adapter).

## Gitea (fast loop)

```bash
docker compose -f deploy/testing/gitea/docker-compose.yml up -d
# open http://localhost:3000 → create the admin user (first-run form)
# then: Settings → Applications → generate a token (scopes: repo)
# create an empty repo, e.g. skills
```

## GitLab CE (acceptance)

```bash
docker compose -f deploy/testing/gitlab/docker-compose.yml up -d
docker compose -f deploy/testing/gitlab/docker-compose.yml logs -f gitlab   # wait for "gitlab Reconfigured!"
docker exec skillctl-gitlab cat /etc/gitlab/initial_root_password           # valid 24h
# open http://localhost:8929 (user: root) → New project → skills
# Settings → Repository → Deploy tokens: name=skillctl, scopes=read_repository,write_repository
#   (or a PAT under User → Access Tokens for the write path)
```

## Wiring the backend to a running forge

The git backend clones/pushes over HTTP; a token-in-URL remote is the simplest
auth for local testing (Deploy-Token credential injection is SPEC-0356 D5):

```bash
# GitLab, PAT or Deploy-Token <TOKEN>:
REMOTE="http://oauth2:<TOKEN>@localhost:8929/root/skills.git"
# Gitea, access token <TOKEN>:
REMOTE="http://<user>:<TOKEN>@localhost:3000/<user>/skills.git"

# smoke test the wire-format by hand:
git clone "$REMOTE" /tmp/skills && ls /tmp/skills
```

## Env-gated Go integration test (next: D6.2)

A `TestGitBackendAgainstRemote` will run only when `M3C_TEST_GIT_REMOTE` is set,
mirroring the `make test-oci` gating idiom — CI's default `test-unit` stays
offline (the bare-repo test in `git_test.go` is the always-on coverage):

```bash
M3C_TEST_GIT_REMOTE="$REMOTE" go test -run TestGitBackendAgainstRemote ./pkg/skillctl/backend/git/
```

## Teardown

```bash
docker compose -f deploy/testing/gitea/docker-compose.yml  down -v   # -v drops the data volume
docker compose -f deploy/testing/gitlab/docker-compose.yml down -v
```
