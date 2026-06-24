// Package evaluation is the SPEC-0280 trust-layer evaluation harness.
//
// It contains no production code: the measurable surface lives entirely in the
// _test.go drivers (one per E-metric, E1–E10) plus the deterministic population
// synthesizer in internal/synth. This file exists only so the package is a
// valid, buildable Go package for `go build ./...` / `go vet ./...` even though
// every driver is a test.
//
// See evaluation/README.md for how to run the harness and reproduce the numbers
// in evaluation/results/, and evaluation/EVALUATION-SECTION.md for the filled
// SPEC-0280 §4 paper-ready Evaluation section.
package evaluation
