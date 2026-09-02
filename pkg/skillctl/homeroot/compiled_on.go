//go:build !windows || allow_home_override_test

package homeroot

// CompiledIn gates whether an explicit $HOME may override the per-user security
// root on Windows (WIN-T8 / WIN-09). It is a COMPILE-TIME constant — deliberately
// NOT an env var, which an attacker who controls the process environment could
// set (the exact WIN-09 re-open the challenge gate flagged). It is true here on
// every non-Windows build (where UserHome's goos short-circuit governs anyway)
// and on any build made with the `allow_home_override_test` tag (the
// dev/quickstart sandbox + the windows-latest test surface). The complementary
// compiled_off.go compiles a false constant for a normal Windows build, so
// shipping Windows releases ignore $HOME.
const CompiledIn = true
