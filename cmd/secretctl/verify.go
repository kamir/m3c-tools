package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"text/tabwriter"
)

// verify asks the service, PER HOLDER, whether the value that holder carries is
// accepted (SPEC-0438 AC-4).
//
// Per holder, not globally, and that is the whole point. A global check answers
// "does some value work", which is true from the first minute of a rotation to
// the last and therefore says nothing about progress. Only a per-place answer
// tells you which of the six places is still on the old value.
//
// With --old the expectation is inverted: the old value must be REFUSED. That
// is the proof a rotation actually finished (AC-5). A new value that works
// proves nothing; the question is whether the old one stopped working.

func cmdVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	regPath := registryFlag(fs)
	old := fs.Bool("old", false, "Expect refusal instead of acceptance: the proof that a rotation finished.")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(stderr, "usage: secretctl verify <name> [--old]")
		return 2
	}

	reg, err := LoadRegistry(*regPath)
	if err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return 1
	}
	entry, err := reg.Find(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "verify: %v\n", err)
		return 1
	}
	if entry.Probe.Kind == "" {
		fmt.Fprintf(stderr, "verify: %q has no probe; without one there is nothing to ask\n", entry.Name)
		return 1
	}

	want, wantWord := entry.Probe.ExpectOK, "angenommen"
	if *old {
		want, wantWord = entry.Probe.ExpectRevoked, "abgewiesen"
	}

	fmt.Fprintf(stdout, "Geheimnis:  %s\n", entry.Name)
	fmt.Fprintf(stdout, "Probe:      %s, erwartet %d (%s)\n\n", entry.Probe.URL, want, wantWord)

	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ORT\tFINGERABDRUCK\tANTWORT\tURTEIL")
	bad := 0
	asked := 0
	for _, h := range entry.Holders {
		if h.Kind == "cloud-run" {
			fmt.Fprintf(tw, "%s\tn/a\tn/a\tuebersprungen\n", h.ID)
			continue
		}
		val, err := ReadHolder(h)
		var absent ErrAbsent
		if errors.As(err, &absent) {
			fmt.Fprintf(tw, "%s\t<leer>\tn/a\tKEIN WERT\n", h.ID)
			bad++
			continue
		}
		if err != nil {
			fmt.Fprintf(tw, "%s\tn/a\tn/a\tUNLESBAR\n", h.ID)
			bad++
			continue
		}
		code, err := entry.Probe.Ask(val)
		if err != nil {
			fmt.Fprintf(tw, "%s\t%s\tn/a\tPROBE FEHLGESCHLAGEN\n", h.ID, val.Fingerprint())
			bad++
			continue
		}
		asked++
		verdict := "ok"
		if code != want {
			verdict = "ABWEICHUNG"
			bad++
		}
		fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", h.ID, val.Fingerprint(), code, verdict)
	}
	_ = tw.Flush()

	fmt.Fprintf(stdout, "\n%d Orte befragt", asked)
	if bad > 0 {
		fmt.Fprintf(stdout, ", %d nicht wie erwartet.\n", bad)
		if *old {
			fmt.Fprintln(stdout, "Solange ein alter Wert noch angenommen wird, hat die Rotation nichts bewirkt.")
		}
		return 1
	}
	fmt.Fprintln(stdout, ", alle wie erwartet.")
	return 0
}
