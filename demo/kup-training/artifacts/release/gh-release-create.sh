#!/usr/bin/env bash
# Run this manually to publish the release. NOT auto-run by build-release.sh.
set -euo pipefail
cd "/Users/kamir/GITHUB.kamir/m3c-tools/demo/kup-training/artifacts/release"
gh release create "skillctl/v0.1.0-kup" \
    --title "skillctl v0.1.0-kup — KuP Berlin training cut" \
    --notes-file RELEASE_NOTES.md \
    --draft \
    skillctl-darwin-arm64 skillctl-darwin-amd64 \
    skillctl-linux-amd64  skillctl-linux-arm64 \
    skillctl-windows-amd64.exe \
    SHA256SUMS install.sh \
    RELEASE_NOTES.md \
    $( [[ -f "/Users/kamir/GITHUB.kamir/m3c-tools/demo/kup-training/artifacts/USER-MANUAL.pdf" ]]                  && echo "/Users/kamir/GITHUB.kamir/m3c-tools/demo/kup-training/artifacts/USER-MANUAL.pdf" ) \
    $( [[ -f "/Users/kamir/GITHUB.kamir/m3c-tools/demo/kup-training/artifacts/SKILLCTL-MANUAL.pdf" ]]              && echo "/Users/kamir/GITHUB.kamir/m3c-tools/demo/kup-training/artifacts/SKILLCTL-MANUAL.pdf" ) \
    $( [[ -f "/Users/kamir/GITHUB.kamir/m3c-tools/demo/kup-training/artifacts/KuP-skill-manager-handbook.pdf" ]]   && echo "/Users/kamir/GITHUB.kamir/m3c-tools/demo/kup-training/artifacts/KuP-skill-manager-handbook.pdf" )
