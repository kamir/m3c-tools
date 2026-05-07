#!/usr/bin/env bash
# kup-hello — the single demo skill action.
# Writes output/hello.txt.
set -euo pipefail
mkdir -p output
printf "Hello from kup-hello — signed, attested, installed by Eric.\n" > output/hello.txt
echo "wrote $(pwd)/output/hello.txt"
