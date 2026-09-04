# Local git-forge test environments (SPEC-0356)

Two disposable forges for testing the skillctl **git artifact backend**
(`pkg/skillctl/backend/git`). The backend is provider-neutral, so the same code
drives both; pick by what you're testing.

| | Gitea | GitLab CE |
|---|---|---|
| Use for | inner loop / CI (git-carrier + generic REST) | GitLab-API acceptance (project access token, protected tags, package registry) |
| Image / RAM | ~150 MB / <512 MB | ~3 GB / ~4 GB floor |
| First boot | ~10 s | ~3-5 min |
| URL | http://localhost:3000 | http://localhost:8929 |

The unit tests in `git_test.go` need **neither**: they run against a local
`git init --bare` repo. These forges are for the **integration** layer (auth +
remote push over HTTP, and the GitLab-specific adapter).

> ⚠️ **The publish credential must be a GitLab *Project Access Token*, not a
> Deploy Token.** `Publish` pushes commits + tags, and GitLab **rejects
> `write_repository` as a deploy-token scope** (`scopes does not have a valid
> value`): deploy tokens are read-only for the git repo. The default branch is
> also protected at **Maintainer** (push level 40), so the token needs
> `access_level: 40`. The backend defaults the git user to `oauth2`, which is
> valid for both a project access token and a PAT, so **no code change is
> needed**: only use the right token type. A Deploy Token is still fine for a
> read-only *consumer* that only fetches.

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
# Settings → Access tokens: name=skillctl, role=Maintainer,
#   scopes=read_repository,write_repository, expiry REQUIRED   (NOT a Deploy token)
```

## Wiring the backend to a running forge

The git backend clones/pushes over HTTP; a token-in-URL remote is the simplest
auth for local testing (a write-capable token; credential injection is
SPEC-0356 D5):

```bash
# GitLab, project access token (Maintainer) <TOKEN>:
REMOTE="http://oauth2:<TOKEN>@localhost:8929/<group>/skills.git"
# Gitea, access token <TOKEN>:
REMOTE="http://<user>:<TOKEN>@localhost:3000/<user>/skills.git"

# smoke test the wire-format by hand:
git clone "$REMOTE" /tmp/skills && ls /tmp/skills
```

## Env-gated Go integration test (D6.2)

`TestGitBackendAgainstRemote` runs only when `M3C_TEST_GIT_REMOTE` is set,
mirroring the `make test-oci` gating idiom. CI's default `test-unit` stays
offline (the bare-repo test in `git_test.go` is the always-on coverage):

```bash
M3C_TEST_GIT_REMOTE="$REMOTE" go test -run TestGitBackendAgainstRemote ./pkg/skillctl/backend/git/
```

**Verified:** PASS in 4.98s (2026-08-28) against the lab GitLab CE 19.3.1 on
`master2` (`http://192.168.0.135:8929`, project `m3c/skills`), credential =
project access token `skillctl-m4` (Maintainer). Full publish → list → resolve
→ fetch byte round-trip confirmed. (GitLab does **not** run on the NAS. A
DS223j with 968 MiB RAM is under GitLab's 4 GiB floor; see the
private maintenance plane for the device note.)

## Operational notes (learned on the lab instance)

- **Publish is idempotent per tag** (`git.go`, `tagExists`): re-publishing an
  existing `<name>/v<version>` returns the existing ref, no re-push. Safe to
  re-run.
- **Protected-tag preflight.** A protected-tag rule matching `*` breaks the
  `git push --tags` step while the blob push (`push HEAD`) succeeds: leaving a
  registry with blobs but no publish tags. Verify none exists:
  `curl -H "PRIVATE-TOKEN: <pat>" .../projects/<id>/protected_tags` (default: empty).
- **The integration test does not clean up.** It names artifacts
  `itest-<unix-nanos>` and leaves them under `skills/`+`events/`. Point CI at a
  throwaway project, or prune periodically: don't run it against a registry you
  actually publish to.
- **Repo growth.** Each op clones the full repo (v1, stateless). Fine for a lab;
  a cached clone + Git LFS for `bundle.skb` are named follow-ups.

## Teardown

```bash
docker compose -f deploy/testing/gitea/docker-compose.yml  down -v   # -v drops the data volume
docker compose -f deploy/testing/gitlab/docker-compose.yml down -v
```
