# Contributing to m3c-tools

Thank you for your interest in contributing to `m3c-tools` and `skillctl`.

## Development Prerequisites

- **Go**: Version 1.25+ (Toolchain 1.26+)
- **System Dependencies** (macOS only, for CGo GUI/Audio):
  ```bash
  brew install pkg-config portaudio ffmpeg
  ```
- **Linting & Tooling**:
  ```bash
  go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
  ```

## Development Workflow

1. **Clone the repository**:
   ```bash
   git clone git@github.com:kamir/m3c-tools.git
   cd m3c-tools
   ```

2. **Run tests**:
   ```bash
   make test-unit   # Run offline unit tests
   make ci          # Run full local CI (vet, lint, test, build)
   ```

3. **Building binaries**:
   ```bash
   make build            # Build m3c-tools CLI
   make build-skillctl   # Build skillctl CLI
   make build-all        # Build all binaries
   ```

## Contribution Guidelines

- **Cleanliness**: Ensure all unit tests pass with `go test -race ./pkg/... ./cmd/skillctl/...`.
- **Hygiene**: Do not commit secrets, environment configs (`.env`), or OS metadata (`.DS_Store`).
- **Commits**: Follow [Conventional Commits](https://www.conventionalcommits.org/) (e.g. `feat(skillctl): add revocation verification`, `fix(er1): retry backoff clamping`).
- **Pull Requests / Merge Requests**: Open PRs against `master` (or customer branch). Ensure CI passes.
