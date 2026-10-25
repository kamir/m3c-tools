package main

import (
	"fmt"
	"os"

	"github.com/kamir/m3c-tools/pkg/skillctl/projectpolicy"
	"github.com/kamir/m3c-tools/pkg/skillctl/verify"
)

// loadInstallProjectPolicy selects operator policy before clients or credentials.
// An empty path preserves legacy unmanaged operation; the library rejects a
// managed mutation that lacks a policy.
func loadInstallProjectPolicy(path, pin, home, registryURL, trustRoots, governance, tenant string, allowYellow, ignoreDeps bool) (*projectpolicy.Policy, int, error) {
	if path == "" {
		if pin != "" {
			return nil, exitUsage, fmt.Errorf("--enterprise-profile-sha256 requires --enterprise-profile")
		}
		return nil, 0, nil
	}
	if trustRoots != "" || governance != "" || tenant != "" || allowYellow || ignoreDeps {
		return nil, exitUsage, fmt.Errorf("enterprise profile forbids trust-root, tenant, governance and dependency overrides")
	}
	cwd, err := os.Getwd()
	if err != nil {
		return nil, 12, fmt.Errorf("enterprise profile: cannot select actual project directory")
	}
	if home == "" {
		home, err = os.UserHomeDir()
		if err != nil {
			return nil, 12, fmt.Errorf("enterprise profile: cannot select artifact home")
		}
	}
	var policy *projectpolicy.Policy
	if pin == "" {
		policy, err = projectpolicy.Load(path, cwd, home)
	} else {
		policy, err = projectpolicy.LoadPinned(path, pin, cwd, home)
	}
	if err != nil {
		return nil, 12, fmt.Errorf("enterprise profile: %w", err)
	}
	if registryURL != "" && policy.ValidateSelection(policy.TrustRoot(), home, registryURL) != nil {
		return nil, exitUsage, fmt.Errorf("enterprise profile registry selection conflicts")
	}
	return policy, 0, nil
}

func installProjectTrustRoots(policy *projectpolicy.Policy, path, registryURL string) (*verify.TrustRoots, *verify.TrustRoot, error) {
	if policy != nil {
		return policy.TrustRoots(), policy.TrustRoot(), nil
	}
	return loadAndPickRootFromPath(path, registryURL)
}
