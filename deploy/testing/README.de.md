# Lokale Git-Forge-Testumgebungen (SPEC-0356)

[Deutsch](README.de.md) · [English](README.md)

Zwei kurzlebige Forges zum Testen des **Git-Artefakt-Backends** von skillctl,
`pkg/skillctl/backend/git`. Das Backend ist anbieterneutral; derselbe Code steuert
beide. Die Auswahl hängt vom Testzweck ab.

| | Gitea | GitLab CE |
|---|---|---|
| Einsatz | Schnelle Entwicklungszyklen und CI, Git-Transport und generisches REST | GitLab-API-Abnahme: Project Access Token, geschützte Tags, Paketregistry |
| Image / RAM | Etwa 150 MB / unter 512 MB | Etwa 3 GB / mindestens etwa 4 GB |
| Erster Start | Etwa 10 s | Etwa 3 bis 5 min |
| URL | http://localhost:3000 | http://localhost:8929 |

Die Unit-Tests in `git_test.go` benötigen **keine** dieser Umgebungen.
Sie nutzen ein lokales `git init --bare`-Repository. Diese Forges dienen der
**Integration**: Authentisierung, Remote-Push über HTTP und GitLab-spezifischer Adapter.

> ⚠️ **Zum Veröffentlichen ist ein GitLab-Project-Access-Token nötig, kein Deploy Token.**
> `Publish` überträgt Commits und Tags. GitLab **lehnt `write_repository` als
> Deploy-Token-Scope ab**, mit `scopes does not have a valid value`.
> Deploy Tokens dürfen das Git-Repository nur lesen. Der Default-Branch ist außerdem
> auf **Maintainer** geschützt, Push-Level 40; das Token benötigt `access_level: 40`.
> Der Git-Nutzer ist standardmäßig `oauth2`, gültig für Project Access Tokens und PATs.
> Es ist deshalb **keine Codeänderung** erforderlich, nur der passende Tokentyp.
> Für einen ausschließlich lesenden **Konsumenten** genügt weiterhin ein Deploy Token.

## Gitea für schnelle Entwicklungszyklen

```bash
docker compose -f deploy/testing/gitea/docker-compose.yml up -d
docker exec -u git skillctl-gitea gitea admin user create --username qa --password '<password>' --email qa@example.invalid --admin --must-change-password=false
docker exec -u git skillctl-gitea gitea admin user generate-access-token --username qa --scopes all --raw
# create an empty repo, e.g. skills
```

## GitLab CE für die Abnahme

```bash
docker compose -f deploy/testing/gitlab/docker-compose.yml up -d
docker compose -f deploy/testing/gitlab/docker-compose.yml logs -f gitlab   # wait for "gitlab Reconfigured!"
docker exec skillctl-gitlab cat /etc/gitlab/initial_root_password           # valid 24h
# open http://localhost:8929 (user: root) → New project → skills
# Settings → Access tokens: name=skillctl, role=Maintainer,
#   scopes=read_repository,write_repository, expiry REQUIRED   (NOT a Deploy token)
```

## Backend mit einer laufenden Forge verbinden

Das Git-Backend klont und pusht über HTTP. Für lokale Tests ist ein Remote mit Token
in der URL die einfachste Authentisierung. Es muss schreiben dürfen;
Credential-Injection ist SPEC-0356 D5:

```bash
# GitLab, project access token (Maintainer) <TOKEN>:
REMOTE="http://oauth2:<TOKEN>@localhost:8929/<group>/skills.git"
# Gitea, access token <TOKEN>:
REMOTE="http://<user>:<TOKEN>@localhost:3000/<user>/skills.git"

# smoke test the wire-format by hand:
git clone "$REMOTE" /tmp/skills && ls /tmp/skills
```

## Über Umgebungsvariable aktivierter Go-Integrationstest (D6.2)

`TestGitBackendAgainstRemote` läuft nur mit gesetztem `M3C_TEST_GIT_REMOTE`, wie beim
Aktivierungsmuster von `make test-oci`. Der normale CI-Lauf `test-unit` bleibt offline.
Der Bare-Repo-Test in `git_test.go` stellt die immer aktive Abdeckung bereit:

```bash
M3C_TEST_GIT_REMOTE="$REMOTE" go test -run TestGitBackendAgainstRemote ./pkg/skillctl/backend/git/
```

**Geprüft:** PASS in 4,98 s am 2026-08-28 gegen GitLab CE 19.3.1 im Labor auf
`master2`, `http://192.168.0.135:8929`, Projekt `m3c/skills`. Credential war das
Project Access Token `skillctl-m4` mit Maintainer-Rechten. Der vollständige Rundlauf
publish → list → resolve → fetch bestätigte identische Bytes. GitLab läuft
**nicht** auf dem NAS: Ein DS223j mit 968 MiB RAM liegt unter GitLabs Mindestbedarf
von 4 GiB. Die Gerätenotiz liegt auf der privaten Maintenance-Ebene.

## Betriebshinweise aus der Laborinstanz

- **Publish ist je Tag idempotent**, siehe `git.go`, `tagExists`. Erneutes Veröffentlichen
  eines vorhandenen `<name>/v<version>` liefert die bestehende Referenz ohne neuen Push.
  Wiederholen ist sicher.
- **Geschützte Tags vorab prüfen.** Eine Schutzregel mit `*` lässt `git push --tags`
  scheitern, während `push HEAD` die Blobs bereits überträgt. Das Registry hat dann
  Blobs ohne Veröffentlichungstags. Sicherstellen, dass keine solche Regel besteht:
  `curl -H "PRIVATE-TOKEN: <pat>" .../projects/<id>/protected_tags`, standardmäßig leer.
- **Der Integrationstest räumt nicht auf.** Er benennt Artefakte `itest-<unix-nanos>`
  und hinterlässt sie unter `skills/` und `events/`. CI auf ein Wegwerfprojekt richten
  oder regelmäßig bereinigen, nicht auf ein tatsächlich genutztes Veröffentlichungsregistry.
- **Repository-Wachstum.** Jede Operation klont in der zustandslosen v1 das gesamte
  Repository. Für ein Labor reicht das; ein gecachter Klon und Git LFS für
  `bundle.skb` sind vorgesehene Folgearbeiten.

## Abbauen

```bash
docker compose -f deploy/testing/gitea/docker-compose.yml  down -v   # -v drops the data volume
docker compose -f deploy/testing/gitlab/docker-compose.yml down -v
```
