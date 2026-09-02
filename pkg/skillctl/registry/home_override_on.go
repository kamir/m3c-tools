//go:build !windows || allow_home_override_test

package registry

// homeOverrideCompiledIn gates whether an explicit $HOME may override the
// registry package's per-user security state (install-token key, self-trust
// roots, caches) on Windows (WIN-T8 / WIN-09). It is a COMPILE-TIME constant —
// deliberately NOT an env var, which an attacker who controls the process
// environment could set (the exact WIN-09 re-open the challenge gate flagged). It
// is true on every non-Windows build (where userHome's goos short-circuit governs
// anyway) and on any build made with the `allow_home_override_test` tag (the
// dev/quickstart sandbox + the windows-latest test surface). The complementary
// home_override_off.go compiles a false constant for a normal Windows build.
const homeOverrideCompiledIn = true
