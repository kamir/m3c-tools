# Deploy ER1 Backend (Local Docker)

Rebuild the aims-core Docker image and restart the local ER1 container.

## When to use

When the user says "deploy", "rebuild backend", "restart ER1", "rebuild Docker", or after making changes to the aims-core Flask app that need to be picked up by the local container.

## What it does

1. **Build** — Rebuilds stages 4-5 of the aims-core Docker image (app layer only, reuses base image cache). This is fast because only the `COPY ./flask` layer changes.
2. **Restart** — Stops the old container, removes it, and starts a fresh one with the new image using the existing `run_image.sh` script.
3. **Verify** — Checks the container is running and the PLM health endpoint responds.

## How to execute

### Step 1: Build the image

Run the existing build script from the aims-core project root. Use the default mode (no flags) which builds stages 4-5 only:

```bash
cd /Users/kamir/GITHUB.active/my-ai-X/aims-core
./tools/RELEASE-v4/build_images_multi_platform_v4.sh
```

This builds:
- Stage 4: `gcr.io/semanpix/aims-core:latest` (Dockerfile — copies flask app)
- Stage 5: `gcr.io/semanpix/aims-core-v4-final:latest` (Dockerfile.refine.pdfs — adds PDFs)

### Step 2: Restart the container

Use the existing run script:

```bash
cd /Users/kamir/GITHUB.active/my-ai-X/aims-core
./tools/v4/run_image.sh
```

This automatically:
- Stops and removes the existing `aims-core-local` container
- Loads env vars from `tools/config/` (shared + docker-local + secrets)
- Mounts `flask/__sec__` and `data/temp_data_stage` volumes
- Starts the new container on port 8081

**Note:** The run_image.sh script tails the logs at the end. The user can Ctrl+C to detach — the container keeps running.

### Step 3: Verify

After the container starts (wait ~5s for Flask to initialize), verify:

```bash
# Health check
curl -sk https://127.0.0.1:8081/api/plm/health

# PLM projects (with API key auth)
curl -sk -H "X-API-KEY: REDACTED_ER1_API_KEY" \
         -H "X-Context-ID: 107677460544181387647___mft" \
         https://127.0.0.1:8081/api/plm/projects
```

Expected: JSON responses (not HTML redirects).

## Important notes

- The build uses `gcr.io/semanpix/baseimage3:latest` as the base. If this image isn't available locally, the first build may pull it from GCR (slow). Subsequent builds are fast.
- The container name is always `aims-core-local`.
- The container runs on port 8081 with HTTPS (self-signed cert).
- Flask code is baked into the image (not volume-mounted), so any code change in `flask/` requires a rebuild.
- Do NOT use `--all` flag unless base image dependencies changed — it rebuilds everything from scratch.
