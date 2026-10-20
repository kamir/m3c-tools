# Guide: documentation by role

Sprachen / Languages: [Deutsch](index.md) | [English](index.en.md)

This page helps you choose the right guide. It is for people opening the repository
for the first time or looking for a particular page. References live under
`referenz/`, user guides under `nutzer/`, operations guides under `betrieb/`;
program, service and component indexes live under `docs/`.

## Authoritative content and language versions

German and English carry the same substantive statements and are reviewed together.
Implementation checks continue reading the existing original paths: docaudit,
verbaudit, exitaudit, tutorial-smoke and check-index. `check-doc-languages.py` checks
language pairs, their digests recorded after review, and identical fenced examples.
Digests detect subsequent changes; they do not prove translation accuracy.
`check-docpages` keeps generated HTML pages synchronized with their sources.

## Start by role

| Role | What you need | Start here |
|---|---|---|
| Users | Installation, first capture, menu bar app and tutorials | [Getting started](nutzer/einstieg.en.md) |
| Development | Architecture, packages and data flow | [Architecture overview](entwickler/architecture.md) |
| Development | Building, testing, quality gates and contributing | [Developer setup](entwickler/getting-started.md) |
| Operations | Registry, tokens, backups, monitoring and incidents | [Operations overview](betrieb/ueberblick.en.md) |
| Security / CISO | Trust model, threats and evidence | [Security overview](sicherheit/ueberblick.en.md) |

## Direct routes

| Page | Content |
|---|---|
| [m3c-tools manual](referenz/manual-m3c-tools.md) | Every command, flag and configuration variable; original checked by docaudit |
| [skillctl manual](referenz/manual-skillctl.md) | Complete trust lifecycle; original checked by docaudit and exitaudit |
| [CLI verbs](referenz/CLI-VERBS.md) | skillctl verb allocation; original checked by verbaudit |
| [Programs](../program-index.md) · [Services](../service-index.md) · [Components](../component-index.md) | Executables, running services and libraries; original program and component indexes checked by check-index |
| [Scenario 01](nutzer/tutorial-szenario-01-eigene-skills-mehrere-maschinen.en.md) · [Scenario 02](nutzer/tutorial-szenario-02-erster-signierter-skill.en.md) · [Katas and Test Ride](nutzer/tutorial-katas-und-test-ride.en.md) | Guided tutorials; scenarios 01 and 02 checked by tutorial-smoke |
| [skillctl-sim](entwickler/skillctl-sim.md) | Read the trust-plane simulation |
| [secretctl](entwickler/secretctl.md) | Check secret holders and freshness without printing values |
| [Audit trail](sicherheit/audit-spur.en.md) | The three audit carriers: audit, auditlog and translog |
| [Technical security evidence](../security/required-checks.txt) | Scanner baselines, release-evidence schema and required checks |
