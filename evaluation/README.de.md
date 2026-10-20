# Evaluierungswerkzeuge der Vertrauensschicht (E1–E10)

[Deutsch](README.de.md) · [English](README.md)

Ein reproduzierbares, eingechecktes Messsystem für die **ausgelieferte** m3c-tools-
Vertrauensschicht: `pkg/skillctl/{verify,signing,translog,agentid,bodyscan,datascope}` und
die CLI `export-verification-kit`. Jede Messgröße verwendet einen Go-Treiber,
der ein tatsächlich ausgeliefertes Paket mit einer **deterministischen** Grundgesamtheit
prüft und eine **echte Zahl** nach `results/RESULTS.csv` und `results/RESULTS.md` schreibt.

**Ehrlichkeitsvertrag nach Projektstandard:** Keine Aussage ohne Zahl. Jede Zeile
trägt `synthetic` für erzeugte Daten oder `real` für den eingecheckten Korpus.
**E6 bleibt `N/A: deferred`**, niemals ein erfundener Wert.

## Was gemessen wird

| # | Messgröße | Treiberdatei | Ausgabe |
|---|---|---|---|
| E1 | Offline-Latenz von `verify` | `e1_verify_latency_test.go` | Median, p99 in ms, kalt und warm |
| E2 | Kit-Prüfung auf einer vom Netz getrennten Maschine | `e2_e9_kit_test.go` | Verstrichene Zeit in ms; **0** Netzaufrufe |
| E3 | Prüfung von Widerrufslisten verschiedener Größe | `e3_revocation_scale_test.go` | Zeit-Größen-Kurve von 10 bis 10⁶ |
| E4 | Verhaltenserkennung TP/FP auf **echtem Korpus** | `e4_bodyscan_corpus_test.go` | TP%, FP% |
| E5 | Zusatzaufwand der Agentenautorisierung | `e5_agent_authz_test.go` | Zusätzliche ms pro Aufruf |
| E6 | Offline-Prüfung von OIDC/JWKS | `e6_oidc_deferred_test.go` | **N/A: deferred (gated P3-P2)** |
| E7 | Prüfung von Inclusion Proofs im Transparenzlog | `e7_inclusion_proof_test.go` | Zeit pro Ereignis in µs als Kurve |
| E8 | Skalierung mit N gepinnten Autoren | `e8_trustroot_scale_test.go` | Zeit-N-Kurve von 1 bis 10³ |
| E9 | Kit-Größe und Reproduzierbarkeit | `e2_e9_kit_test.go` | Bytes und Bytegleichheit |
| E10 | Korrektheit der Widerrufsfrische | `e10_freshness_test.go` | Pass-/Fail-Matrix |

Gemeinsame Bestandteile:

- `internal/synth/synth.go`: deterministischer Aussteller nach dem Whitepaper-Muster
  `mint-evidence.go`, reproduzierbar durch seedbasierte ed25519-Schlüssel.
  Erzeugt N signierte `.skb`-Bundles, `BundleMeta` und einen gepinnten `TrustRoot`,
  der vollständig offline prüfbar ist.
- `harness_test.go`: Ergebnissenke nach `results/RESULTS.csv`.
- `scripts/mint_kit_fixture.go`: Aussteller mit `go:build ignore`, der E2/E9 eine
  deterministische Fixture für das echte `skillctl export-verification-kit` liefert.

## Ausführen

```bash
# Fast correctness pass (no RUN_EVAL): E4 (real corpus) + E10 (safety matrix).
# These run in plain CI and fail the build on a regression.
go test ./evaluation/

# Full measured harness: produces results/RESULTS.csv (overwrite is gated on
# RUN_EVAL so a plain `go test ./...` never clobbers committed numbers).
RUN_EVAL=1 go test ./evaluation/ -run 'TestE|TestZZZ' -v -timeout 30m

# Then regenerate the Markdown table from the CSV:
go run ./evaluation/cmd/results-md
```

### Determinismus und Seeds

Jeder Treiber verwendet einen festen Seed, die Konstanten `e1Seed … e10Seed`.
Der Generator leitet alle Schlüssel daraus über eine SHA-256-KDF im Zählermodus ab.
Derselbe Seed liefert deshalb bei jedem Lauf und auf jedem Host eine **bytegleiche**
Grundgesamtheit mit identischen Digests. Die Seeds stehen am Anfang jeder Treiberdatei.

> Das Verbot von `Date.now()` für Workflow-Skripte gilt **nicht** für Go.
> Die Treiber verwenden `time.Now()` ausschließlich zum *Messen* verstrichener Zeit,
> niemals als Datenseed, sowie `testing.B` für die Benchmarkvarianten.

### Benchmarkvarianten zur Gegenprüfung

Mehrere Messgrößen bieten zusätzlich einen `testing.B`-Benchmark für eine unabhängige
Messung in `ns/op` auf einem einzelnen Kern:

```bash
go test ./evaluation/ -run x -bench 'E1|E5|E7' -benchmem -cpu 1
```

## Hinweise zur Methodik

- **E1 kalt und warm.** *Kalt* prüft unterschiedliche Bundles, sodass jedes `verify`
  SHA-256 über Bytes berechnet, die der vorige Aufruf nicht berührt hat. *Warm*
  prüft dasselbe bereits verwendete Bundle und isoliert Kryptografie und Kettenprüfung.
  Für einen Kern `-cpu 1` an den Benchmark übergeben. Der Latenztest verwendet
  konstruktionsbedingt nur eine Goroutine.
- **E2 Nachweis ohne Netz.** Ein **Sentinel**-TCP-Listener auf localhost zählt eingehende
  Verbindungen. Alle Proxyvariablen, `HTTP(S)_PROXY`, `ALL_PROXY` und Kleinbuchstabenvarianten,
  zeigen darauf. Der Prüfpfad verwendet gepinnte Schlüssel und liest keine Registry-/ER1-Endpunkte.
  Jeder HTTP-Egress würde deshalb am Sentinel ankommen und gezählt.
  Die Zusicherung lautet `net_calls == 0`. Für eine stärkere Garantie auf Systemaufrufebene
  die Prüfung unter einem Tracer ausführen:
  - Linux: `strace -f -e trace=network skillctl verify --bundle … --trust-roots …`
  - macOS: `sudo dtruss -t connect skillctl verify …`
  Beide sollten keine `connect()`-Aufrufe an Nicht-Loopback-Adressen zeigen.
- **E4 nutzt den ECHTEN eingecheckten Korpus** unter
  `../pkg/skillctl/bodyscan/testdata/corpus`, mit 40 adversarialen und 32 harmlosen Fällen.
  TP/FP verwenden dieselbe Korrektheitsanforderung wie die ausgelieferte Verhaltensprüfung.
  E4 misst somit das tatsächliche produktive Abnahmekriterium erneut.
- **E5** liefert *zwei* Werte: Prüfung eines gecachten Mandats, nur `AuthorizeSkill`,
  und erneute Verifikation je Aufruf, `agentid.Verify` plus `AuthorizeSkill`.
  Beide sind die Differenz zu einer Baseline ohne Gate.
- **E9** exportiert das Kit zweimal aus derselben deterministischen Fixture und vergleicht
  Datei für Datei. Reproduzierbar bedeutet: jede Datei bytegleich.
- **E10** misst Korrektheit statt Latenz. Jeder Angriffsfall, rollback, stale-high,
  stale-low-open, fresh, future-dated, split-view und consistency, nutzt die ausgelieferten
  Funktionen `EvaluateFreshness`, `VerifyRevocationList`, `VerifyConsistency` und
  `DetectSplitView` und prüft das **sichere** Urteil.

## Grenzen der Aussagekraft

Die Grundgesamtheit ist **synthetisch**, außer E4 mit echtem Korpus.
Ergebnisse stammen von **einer Plattform**; Hardwaredetails stehen im erzeugten
Bericht `results/RESULTS.md`. Die **Repräsentativität** des Korpus begrenzt E4.
E6 bleibt ausdrücklich zurückgestellt.

## Rahmenbedingung

Das Messsystem ist **additiv**: Es liegt vollständig unter `evaluation/` und verändert
**kein** ausgeliefertes Paket. Es verwendet ausschließlich vorhandene exportierte APIs.
