package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
)

// inventory answers the question nobody could answer on 2026-09-15: who holds
// this secret, and does each of them hold the CURRENT one (SPEC-0438 §3, AC-3).
//
// It is the first command of a rotation, before `new`. A rotation does not fail
// at the value; it fails at the copy nobody listed.

type holderState struct {
	Holder Holder
	FP     string // fingerprint, or a word saying why there is none
	Status string // "aktuell" | "veraltet" | "fehlt" | "unlesbar" | "n/a"
	Detail string
}

func cmdInventory(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("inventory", flag.ContinueOnError)
	fs.SetOutput(stderr)
	regPath := registryFlag(fs)
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: secretctl inventory <name>")
		return 2
	}

	reg, err := LoadRegistry(*regPath)
	if err != nil {
		fmt.Fprintf(stderr, "inventory: %v\n", err)
		return 1
	}
	entry, err := reg.Find(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "inventory: %v\n", err)
		return 1
	}

	active, sourceErr := ReadSource(entry.Source)
	states := inspect(entry, active, sourceErr == nil)

	fmt.Fprintf(stdout, "Geheimnis:  %s\n", entry.Name)
	fmt.Fprintf(stdout, "            %s\n", entry.Summary)
	if sourceErr != nil {
		fmt.Fprintf(stdout, "Quelle:     NICHT LESBAR (%v)\n", sourceErr)
		fmt.Fprintf(stdout, "            Ohne die Quelle ist kein Abgleich moeglich; die Spalte Stand bleibt leer.\n")
	} else {
		fmt.Fprintf(stdout, "Quelle:     %s/%s, aktive Fassung %s\n",
			entry.Source.Project, entry.Source.Secret, active.Fingerprint())
	}
	fmt.Fprintln(stdout)

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ORT\tART\tMASCHINE\tFINGERABDRUCK\tSTAND")
	veraltet, fehlend, unlesbar, unerreichbar := 0, 0, 0, 0
	for _, s := range states {
		host := s.Holder.Host
		if host == "" {
			host = "lokal"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			s.Holder.ID, s.Holder.Kind, host, s.FP, s.Status)
		switch s.Status {
		case "veraltet":
			veraltet++
		case "fehlt":
			fehlend++
		case "unlesbar":
			unlesbar++
		case "unerreichbar":
			unerreichbar++
		}
	}
	_ = tw.Flush()

	for _, s := range states {
		if s.Detail != "" {
			fmt.Fprintf(stdout, "  %s: %s\n", s.Holder.ID, s.Detail)
		}
	}

	fmt.Fprintf(stdout, "\n%d Orte gefuehrt", len(states))
	if veraltet+fehlend+unlesbar+unerreichbar > 0 {
		fmt.Fprintf(stdout, ", davon %d veraltet, %d ohne Wert, %d unlesbar, %d unerreichbar",
			veraltet, fehlend, unlesbar, unerreichbar)
	}
	fmt.Fprintln(stdout, ".")

	if unerreichbar > 0 {
		fmt.Fprintf(stdout, "\n%d Ort(e) konnten nicht befragt werden. Das Inventar ist damit UNVOLLSTAENDIG,\n", unerreichbar)
		fmt.Fprintln(stdout, "und kein Schritt einer Rotation darf auf dieser Grundlage als erledigt gelten.")
		return 1
	}
	if veraltet > 0 || fehlend > 0 {
		fmt.Fprintln(stdout, "\nEine Rotation ist erst abgeschlossen, wenn hier kein Ort mehr veraltet ist.")
		return 1
	}
	return 0
}

// inspect reads every holder and classifies it. Pure enough to test: it takes
// the active value rather than fetching it.
func inspect(entry *Entry, active Secret, haveSource bool) []holderState {
	out := make([]holderState, 0, len(entry.Holders))
	for _, h := range entry.Holders {
		st := holderState{Holder: h}

		if h.Kind == "cloud-run" {
			// A running service does not hand its environment back. What can
			// be read is the binding, and the honest report says so rather
			// than pretending to have compared a value.
			v, err := BoundVersion(h)
			switch {
			case err != nil:
				st.FP, st.Status = "n/a", "unlesbar"
				st.Detail = fmt.Sprintf("Bindung nicht lesbar (%v)", err)
			default:
				st.FP, st.Status = v, "n/a"
				st.Detail = "Ein Dienst gibt seine Umgebung nicht heraus. Ob der Wert wirklich gilt, sagt `verify`, nicht diese Zeile."
			}
			out = append(out, st)
			continue
		}

		val, err := ReadHolder(h)
		var absent ErrAbsent
		var unreach ErrUnreachable
		switch {
		case errors.As(err, &unreach):
			// NOT "fehlt". A place that could not be asked is an open
			// question, and an open question must never be counted as a
			// finished one.
			st.FP, st.Status = "?", "unerreichbar"
			st.Detail = unreach.Reason + ". Solange dieser Ort nicht befragt werden kann, ist das Inventar unvollstaendig."
		case errors.As(err, &absent):
			st.FP, st.Status = "<leer>", "fehlt"
		case err != nil:
			st.FP, st.Status = "n/a", "unlesbar"
			st.Detail = err.Error()
		default:
			st.FP = val.Fingerprint()
			switch {
			case !haveSource:
				st.Status = "?"
			case val.SameAs(active):
				st.Status = "aktuell"
			default:
				st.Status = "veraltet"
			}
		}
		out = append(out, st)
	}
	return out
}
