# Runbook: skillctl-sim, die Simulation der Vertrauensebene

Sprachen / Languages: [Deutsch](skillctl-sim.de.md) | [English](skillctl-sim.md)

Wie `cmd/skillctl-sim` ausgeführt und vor allem seine Ausgabe gelesen wird.
Alles Folgende wurde am 2026-09-16 aus `cmd/skillctl-sim/main.go`,
`pkg/skillctl/sim/` und dem `Makefile` (`sim`, `sim-deep`, `sim-theory`) gelesen.

Zielgruppe: Entwickler nach einer Änderung der Vertrauensebene, die das
Urteil aus Theorie und Messung benötigen, oder bei einem roten `make sim`
entscheiden müssen, was es bedeutet. Der einzeilige Indexeintrag steht im
[Program-Index](../../program-index.de.md).

Rolle: Entwickler · Sprache: DE · Stand: 2026-09-16

## Was es ist, in einem Satz

Ein erzeugter Korpus aus Szenarien mit mehreren Prinzipalen und jeweils einer
aus der SPEC abgeleiteten Vorhersage, ausgeführt gegen das **echte**
`skillctl`-Binary und ein echtes Git-Registry, hermetisch (ein Wegwerf-HOME
je Szenario); der Lauf vergleicht die vorhergesagte Ergebnisverteilung mit
der gemessenen, Kategorie für Kategorie.

## Die vier Unterbefehle

Dispatch aus `main()` in `cmd/skillctl-sim/main.go` gelesen:

| Unterbefehl | Funktion | Exit |
|---|---|---|
| `theory` | Prüft allein die SPEZIFIKATION, ohne Binary, Registry oder Netz; analysiert den Zustandsraum. | `0` stimmig · `1` das Modell besteht die eigene Prüfung nicht · `2` Usage |
| `list` | Gibt den erzeugten Korpus und die Vorhersage je Szenario aus; `[OUT OF MODEL]` kennzeichnet nicht beanspruchte Schritte. | `0` · `2` Usage |
| `run` | Führt den Korpus gegen das getestete Binary aus und vergleicht Theorie und Wirklichkeit. | `0` bestanden · `1` fehlgeschlagen · `2` Usage |
| `freeze` | Gibt das Freeze-Manifest für eine geplante Messung aus (`-t`, `-plan`, `-scope`). | `0` · `1` Fehler · `2` Usage |

Flags für `run`: `-t` (Stärke des Covering Arrays: `2` = Gate, `3` =
wöchentlicher Lauf, `0` = kein Versuchsplan, dann zählt `-n`), `-n`,
`-skillctl <path>` (Vorgabe `./build/skillctl`, danach PATH), `-jobs`,
`-md <file>` (Bericht zusätzlich als Markdown schreiben).

## Ausführen

```bash
make sim          # strength 2: the blocking gate, about four seconds
make sim-deep     # strength 3: where three-way interactions show up; weekly
make sim-theory   # the specification alone, no binary in the loop
```

Der Korpus mit Stärke 2 ist ein COVERING ARRAY, keine Stichprobe: Jedes
zulässige Paar von Faktorstufen kommt in mindestens einem Szenario vor.
Breite ist damit eine rechnerische Eigenschaft statt Ermessenssache
(Makefile, Kommentar zu `sim`).

## Einen Lauf lesen

Die Bestehensbedingung aus der Exit-Logik von `runRun`
(`cmd/skillctl-sim/main.go`):

1. **Harness-Fehler haben Vorrang.** Ein Harness-Fehler bedeutet, dass der
   Korpus nicht lief: Der Lauf "measured nothing and is not a result" und
   endet unabhängig von der Konfliktzahl mit Exit `1`. Diese Regel existiert,
   weil ein Lauf ohne ausgeführtes Szenario einmal mit `0` endete.
2. **Kein Konflikt ohne Freistellung.** Ein freigestellter Konflikt wird mit
   seinem Befund gezählt und ausgegeben; er wird nicht aus dem Vergleich entfernt.
3. **Keine verletzte Invariante.**
4. **Residuum null.** Das Residuum ist die gesamte Abweichung zwischen der
   geschlossenen Vorhersageformel und der gemessenen Verteilung. Es gehört
   zur Bestehensbedingung: Die frühere Ausnahme ("out-of-model attacks make
   some residual permanent") ist ersetzt, weil das analytische Modell diese
   Ergebnisse (zurückgehaltener Widerruf, gestohlener Schlüssel) nun
   vorhersagt, statt von ihnen überrascht zu werden; die Begründung steht
   am Target `sim` im Makefile.

Jeder Bericht enthält Herkunftsnachweise: Harness-Commit, Modell-Hash,
Binary-Hash und die eigene `--version`-Antwort des Binaries. Lautet sie
`dev`, ist das selbst ein Befund: Das gemessene Artefakt ist kein
veröffentlichtes (`sutVersion`, `cmd/skillctl-sim/main.go`).

## Zwei gemessene Fallstricke

- **Der Binary-Pfad wird vor dem Worker-Start absolut aufgelöst.** Jedes
  Szenario läuft in einem eigenen Arbeitsverzeichnis; ein relativer
  `-skillctl`-Pfad ließ früher jeden exec-Aufruf fehlschlagen, während der
  Lauf dennoch mit `0` endete. `resolveBinary` löst und prüft den Pfad nun
  vorab und scheitert einmal mit dem konkreten Pfad.
- **`run` benötigt ein Binary, `theory` nicht.** Ein fehlendes Binary wird
  vor dem ersten Szenario verweigert ("no skillctl found; build one with
  `make build-skillctl` or pass `-skillctl <path>`"), statt je Szenario einen
  Fehler auszulösen.
