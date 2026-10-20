# Release-Nachweise für Trust Freeze

[Deutsch](README.de.md) | [English](README.md)

Welche Aussagen eine Plattform über Trust Freeze machen darf und was sie belegt.
Die Stufen sind eigenständige Aussagen und werden niemals zu einem einzigen Wort
wie „unterstützt“ zusammengezogen (SPEC-0471, TF06-R6 und TF06-R7):

| Stufe | Bedeutung |
|---|---|
| `implemented` | Der Codepfad für diese Plattform existiert. |
| `fixture-tested` | Parser und Entscheidungen sind durch auf beliebigen Rechnern ausführbare Tabellentests und Testdaten abgedeckt. |
| `cross-compiled` | `go vet` ist fehlerfrei und Testbinärdateien lassen sich für das Ziel linken; dort wurde nichts ausgeführt. |
| `real-platform-tested` | Testbinärdateien und Abnahmepfad wurden auf dieser Plattform tatsächlich ausgeführt, an einen Commit gebunden. |

Cross-Kompilierung ist kein Plattformtest. Ein Lauf für einen früheren Commit
belegt keinen späteren.

Eine im Code ausdrücklich benannte Ausnahme von „auf beliebigen Rechnern
ausführbar“: Szenarien von `linux.executables`, die `/proc/<pid>/exe` lesen,
werden unter Windows übersprungen. Das Ziel dieses Kernel-Links ist ein absoluter
POSIX-Pfad; ein unter Windows im Test erstellter Symlink enthält dagegen einen
Laufwerksbuchstaben (`executables_test.go`, `execSkipWithoutProcExe`). Parser,
Artefaktgestaltung, Grenzen und sämtliche Verweigerungen dieser Probe laufen
auch unter Windows, wie alle übrigen Fixture-Tests der Linux-Familie.

`release-matrix.json` hält je RUNDE und Plattform fest, was für einen Commit
tatsächlich lief: Unit-Test-Anzahlen, Ergebnis des Abnahmeskripts,
maschinenübergreifende Prüfungen und bei Runden mit echten Erfassungen die
Probenergebnisse und Befunde. Die Datei enthält keine Hostnamen, Adressen oder
Nutzernamen. Ein Bundle beschreibt zwar seinen Host, diese Nachweisdatei jedoch nicht.

Jede Runde führt außerdem `defects_found_by_these_runs` auf. Diese Liste begründet,
warum überhaupt auf echten Rechnern getestet wird: T-03 fand sechs Fehler, die
49 Fixtures und drei Review-Runden nicht gefunden hatten. Darunter war eine
Redaktionsmarkierung, die durch Doppelpunkte getrennte Einträge beschädigte und
das root-Konto aus dem Bundle entfernte.

Umfang der zwei bisher erfassten Runden: T-01 ist das durchgängig lauffähige
Grundgerüst mit `common.identity` und Bundle-Lebenszyklus. T-03 ergänzt neun
Linux-Proben und das Profil `ubuntu-bastion`, ausgeführt auf zwei echten
Ubuntu-Rechnern, darunter ein Bastion-Host. TF06-AC1, echter Linux-Lauf der
verpflichtenden Proben, wird deshalb für die Linux-Runde beansprucht.
TF06-AC2 für Windows/WSL und TF06-AC3 für macOS-Probenfamilien dagegen NICHT,
weil diese Familien nicht existieren. TF06-AC4, maschinenübergreifende Prüfung,
wird für beide Runden beansprucht.

T-03b ergänzt die drei zuvor fehlenden Proben `linux.network.routes`, `linux.dns`
und `linux.executables`. Das Profil `ubuntu-bastion` steigt auf Version `3`;
seine Pflichtliste ist nun die vollständige Liste aus SPEC-0471 TF06-R3.
Daraus folgen zwei Dinge, die beide keinen tatsächlichen Lauf behaupten:

- Was diese Datei über echte Läufe der drei neuen Proben aussagt, bestimmt der
  Rundeneintrag in `release-matrix.json`, nicht dieser Absatz. Bis entsprechende
  Einträge existieren, gelten ausschließlich `implemented`, `fixture-tested`
  und `cross-compiled`. Die zugehörigen Testdaten wurden auf zwei echten
  Ubuntu-Rechnern gelesen; dies belegt deren Herkunft, nicht einen Plattformtest
  der Proben. Der `scope`-Text von T-03 in `release-matrix.json` sagt weiterhin,
  dass Routen, DNS und Hashes ausführbarer Dateien nicht implementiert sind.
  Das bleibt bewusst unverändert: Eine Runde nennt ihren Commit (`744d015`)
  und dokumentiert den damaligen Stand. Sie wird durch eine spätere Runde
  abgelöst, niemals nachträglich geändert.
- Ein Host mit letzter Erfassung `complete` gegen `ubuntu-bastion` Version `2`
  gilt gegen Version `3` als `incomplete`, bis die drei neuen Proben dort
  ausgeführt wurden. Das ist weder eine Regression des Hosts noch des Werkzeugs:
  Eine weiter gefasste Frage macht eine ältere Antwort nicht vollständiger.
  Abhilfe sind neue Erfassung und neue Genehmigung; die Vollständigkeitslücke
  benennt jede noch nicht ausgeführte Probe.

Zur Aktualisierung auf jeder Plattform `go test -count=1 ./pkg/skillctl/trustfreeze/... ./cmd/skillctl/`
und `./scripts/trustfreeze-acceptance.sh` gegen einen sauberen Checkout des
Commits ausführen; anschließend den Eintrag manuell aktualisieren.
