# Deploy to GCP (Cloud Run)

Build the aims-core Docker image and deploy to Google Cloud Run.

## When to use

When the user says "deploy to GCP", "deploy to cloud", "deploy stage", "deploy production", "redeploy", "push to GCP", or wants to update the running Cloud Run service.

## What it does

1. **Ask** — Reads defaults from `.deploy/gcp-defaults.env` and asks the user which environment to target, with option to override defaults.
2. **Check** — Validates prerequisites (gcloud auth, Docker, aims-core checkout).
3. **Build** — Builds the Docker image using the aims-core build pipeline.
4. **Deploy** — Pushes the image and deploys to Cloud Run.
5. **Verify** — Checks the Cloud Run service is healthy.
6. **Record** — Updates `.deploy/gcp-state.json` with deployment details.

## How to execute

### Step 1: Load defaults and ask the user

Read `.deploy/gcp-defaults.env` and `.deploy/gcp-state.json` from the m3c-tools project root.

Use the AskUserQuestion tool to present deployment options:

**Question 1 — "Where should we deploy?"**
- Options: `stage-legacy` (semanpix — default), `stage-new` (aims-core-stage / stage.onboarding.guide), `production` (aims-core-prod / api.maindset.academy)
- Show the last deployment timestamp from gcp-state.json for each environment if available.

**Question 2 — "What deploy action?"**
- `Quick redeploy` — Rebuild app layer only (stages 4-5), push and deploy. Fast. (Recommended)
- `Full rebuild` — Rebuild all 5 stages from scratch, push and deploy. Slow.
- `Build only` — Build and push image but do not deploy to Cloud Run.
- `Dry-run` — Check prerequisites, show resolved config and commands, but do not build or deploy.

If the user selected `production`, add an extra confirmation: "You selected PRODUCTION. This affects live users. Type YES to confirm."

### Step 2: Check prerequisites

Run these checks and report results before proceeding:

```bash
# 1. Check gcloud is installed and authenticated
gcloud auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null

# 2. Check Docker is running
docker info --format '{{.ServerVersion}}' 2>/dev/null

# 3. Check aims-core checkout exists
AIMS_CORE_ROOT=$(grep AIMS_CORE_ROOT .deploy/gcp-defaults.env | cut -d= -f2)
test -d "${AIMS_CORE_ROOT}/flask"

# 4. Check buildx builder exists
docker buildx inspect aims-multiplatform 2>/dev/null
```

If gcloud is not authenticated, tell the user to run:
```bash
gcloud auth login
gcloud auth configure-docker gcr.io
```

If the buildx builder doesn't exist, create it:
```bash
docker buildx create --name aims-multiplatform --driver docker-container --bootstrap
```

If any other check fails, stop and tell the user what to fix.

### Step 3: Discover current service state

Before building, check the actual Cloud Run service:
```bash
# List services in the target project to find the correct service name
gcloud run services list --project=${GCP_PROJECT} --region=${GCP_REGION} \
    --format="table(metadata.name,status.url)" 2>&1
```

**IMPORTANT — Service name mapping** (from dry-run 2026-03-12):
- `stage-legacy`: actual service name is `aims-core-v4` (NOT `aims-core-v4-stage` as in env file)
- `stage-new`: service name is `aims-core-stage`
- `production`: service name is `aims-core`

Always use the service name from `.deploy/gcp-state.json` (which has the corrected names), NOT from the env file's `CLOUD_RUN_SERVICE_NAME`.

### Step 4: Build the image

Navigate to the aims-core project root and run the build.

**For Quick redeploy** (stages 4-5 only — the common case):
```bash
cd ${AIMS_CORE_ROOT}

# Source the environment config
set -a
source tools/config/shared/common.env
source tools/config/environments/${TARGET_ENV}.env
set +a

# Authenticate with GCR
if [ "${TARGET_ENV}" = "stage-legacy" ]; then
    docker login -u _json_key --password-stdin https://gcr.io < flask/__sec__/semanpix-admin-key.json
else
    gcloud auth configure-docker gcr.io
    gcloud config set project "${GCP_PROJECT}"
fi

# Use the buildx builder
docker buildx use aims-multiplatform

# Build app image (stage 4) — uses cached base image
REGISTRY="gcr.io/${GCP_PROJECT}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

# For non-semanpix projects: Dockerfile FROM references gcr.io/semanpix/baseimage3:latest
# which is correct for stage-legacy. For other envs, create a temp Dockerfile:
if [ "${GCP_PROJECT}" != "semanpix" ]; then
    cp Dockerfile Dockerfile.tmp
    sed -i.bak "s|FROM gcr.io/semanpix/baseimage3:latest|FROM ${REGISTRY}/baseimage3:latest|g" Dockerfile.tmp
    BUILD_DOCKERFILE="Dockerfile.tmp"
else
    BUILD_DOCKERFILE="Dockerfile"
fi

docker buildx build \
    --platform ${BUILD_PLATFORMS} \
    -f ${BUILD_DOCKERFILE} \
    --target build4 \
    -t ${REGISTRY}/aims-core:latest \
    -t ${REGISTRY}/aims-core:v4 \
    -t ${REGISTRY}/aims-core:v4-${TIMESTAMP} \
    --load \
    .

# Push tags
docker push ${REGISTRY}/aims-core:latest
docker push ${REGISTRY}/aims-core:v4
docker push ${REGISTRY}/aims-core:v4-${TIMESTAMP}

# Build final image with PDFs (stage 5)
# Dockerfile.refine.pdfs has: FROM gcr.io/semanpix/aims-core:latest
# For non-semanpix, need to fix the FROM line:
if [ "${GCP_PROJECT}" != "semanpix" ]; then
    cp Dockerfile.refine.pdfs Dockerfile.refine.pdfs.tmp
    sed -i.bak "s|FROM gcr.io/semanpix/aims-core:latest|FROM ${REGISTRY}/aims-core:latest|g" Dockerfile.refine.pdfs.tmp
    FINAL_DOCKERFILE="Dockerfile.refine.pdfs.tmp"
else
    FINAL_DOCKERFILE="Dockerfile.refine.pdfs"
fi

docker buildx build \
    --platform ${BUILD_PLATFORMS} \
    -f ${FINAL_DOCKERFILE} \
    --target build5 \
    -t ${REGISTRY}/aims-core-final:latest \
    -t ${REGISTRY}/aims-core-final:v4 \
    -t ${REGISTRY}/aims-core-final:v4-${TIMESTAMP} \
    --load \
    .

# Push tags
docker push ${REGISTRY}/aims-core-final:latest
docker push ${REGISTRY}/aims-core-final:v4
docker push ${REGISTRY}/aims-core-final:v4-${TIMESTAMP}

# Cleanup temp files
rm -f Dockerfile.tmp Dockerfile.tmp.bak Dockerfile.refine.pdfs.tmp Dockerfile.refine.pdfs.tmp.bak
```

**For Full rebuild** (all 5 stages):
```bash
cd ${AIMS_CORE_ROOT}
./tools/v4/build_and_deploy.sh ${TARGET_ENV} ${BUILD_PLATFORMS}
```
Note: This script is interactive (asks to deploy at the end). When using it, answer Y to deploy.

### Step 5: Deploy to Cloud Run

Skip this step if "Build only" or "Dry-run" was selected.

Read the correct service name from `.deploy/gcp-state.json` for the target environment.

```bash
cd ${AIMS_CORE_ROOT}

# Source configs
set -a
source tools/config/shared/common.env
source tools/config/environments/${TARGET_ENV}.env
set +a

REGISTRY="gcr.io/${GCP_PROJECT}"

# IMPORTANT: Use the correct service name from gcp-state.json, NOT from env file
# stage-legacy: aims-core-v4
# stage-new: aims-core-stage
# production: aims-core
SERVICE_NAME="<read from gcp-state.json>"

# Set GCP project
gcloud config set project "${GCP_PROJECT}"

# Build environment variables string for Cloud Run
# NOTE: For stage-legacy, FN_BASE_URI in the env file has a placeholder.
# After first deploy, get the real URL and use it:
#   gcloud run services describe ${SERVICE_NAME} --region=${GCP_REGION} --format='value(status.url)'
ENV_VARS="ENV=${ENV}"
ENV_VARS="${ENV_VARS},DEBUG=${DEBUG}"
ENV_VARS="${ENV_VARS},PORT=${PORT}"
ENV_VARS="${ENV_VARS},SERVER_NAME=${SERVER_NAME}"
ENV_VARS="${ENV_VARS},ALLOWED_HOSTS=${ALLOWED_HOSTS}"
ENV_VARS="${ENV_VARS},ADMIN_USERS=${ADMIN_USERS}"
ENV_VARS="${ENV_VARS},DEPLOYMENT_FLAVOR=${DEPLOYMENT_FLAVOR}"
ENV_VARS="${ENV_VARS},USE_SSL_ON_APP=${USE_SSL_ON_APP}"
ENV_VARS="${ENV_VARS},PROJECT_ID=${PROJECT_ID}"
ENV_VARS="${ENV_VARS},GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}"

# Deploy
gcloud run deploy ${SERVICE_NAME} \
    --image=${REGISTRY}/aims-core-final:latest \
    --region=${GCP_REGION} \
    --platform=managed \
    --allow-unauthenticated \
    --cpu=${CLOUD_RUN_CPU} \
    --memory=${CLOUD_RUN_MEMORY} \
    --min-instances=${CLOUD_RUN_MIN_INSTANCES} \
    --max-instances=${CLOUD_RUN_MAX_INSTANCES} \
    --concurrency=${CLOUD_RUN_CONCURRENCY} \
    --set-env-vars="${ENV_VARS}"
```

After deploy succeeds, get the real service URL and set the URL-dependent env vars:
```bash
SERVICE_URL=$(gcloud run services describe ${SERVICE_NAME} \
    --region=${GCP_REGION} --format='value(status.url)')

# Update FN_BASE_URI and GOOGLE_AUTH_REDIRECT_URI with real URL
gcloud run services update ${SERVICE_NAME} \
    --region=${GCP_REGION} \
    --update-env-vars="FN_BASE_URI=${SERVICE_URL},GOOGLE_AUTH_REDIRECT_URI=${SERVICE_URL}/google/auth"
```

For non-legacy environments, also set secrets from Secret Manager:
```bash
if [ "${TARGET_ENV}" != "stage-legacy" ]; then
    gcloud run services update ${SERVICE_NAME} \
        --region=${GCP_REGION} \
        --set-secrets="SECRET_KEY=flask-secret-key:latest,OPENAI_API_KEY=openai-api-key:latest,GOOGLE_CLIENT_SECRET=google-client-secret:latest,YOUTUBE_DATA_API_KEY=youtube-api-key:latest,PUBLISHABLE_KEY=stripe-publishable-key:latest"
fi
```

### Step 6: Verify deployment

```bash
# Get the service URL
SERVICE_URL=$(gcloud run services describe ${SERVICE_NAME} \
    --region=${GCP_REGION} \
    --format='value(status.url)' 2>/dev/null)

echo "Service URL: ${SERVICE_URL}"

# Health check (wait a few seconds for cold start)
sleep 5
curl -sk "${SERVICE_URL}/api/plm/health" --max-time 15
```

Report the service URL and health status to the user.

### Step 7: Update deployment state

Update `.deploy/gcp-state.json` in the m3c-tools project:
- Set `last_deployment` to current ISO timestamp
- Update the target environment's `last_deployed` to current ISO timestamp
- Update the `image` tag with the timestamped version used
- Record the service URL

Use the Edit tool to update the JSON file.

## Important notes

- The `aims-core` source is at `/Users/kamir/GITHUB.active/my-ai-X/aims-core` (configurable in `.deploy/gcp-defaults.env`).
- The build uses `gcr.io/${GCP_PROJECT}/baseimage3:latest` as base. If missing, the first build will be slow.
- `stage-legacy` (semanpix) uses a service account key file for GCR auth. Other environments use `gcloud auth`.
- Production deployments require explicit YES confirmation.
- Quick redeploy assumes base images (stages 1-3) are already in the registry. If they aren't, use Full rebuild.
- The buildx builder `aims-multiplatform` is shared across deployments.
- After deployment, show the user the deployment summary: environment, image tag, service URL, and timestamp.
- **Service name gotcha**: The env file `CLOUD_RUN_SERVICE_NAME` for stage-legacy says `aims-core-v4-stage`, but the actual GCP service is `aims-core-v4`. Always use the name from `gcp-state.json`.
- **FN_BASE_URI gotcha**: The stage-legacy env file has a placeholder `REPLACE_WITH_ACTUAL_URL`. After first successful deploy, get the real Cloud Run URL and set it via `--update-env-vars`.
- **Dockerfile FROM lines**: Dockerfiles hardcode `gcr.io/semanpix/...`. For non-semanpix projects, create temp copies with sed-replaced FROM lines (cleaned up after build).

## GCP setup (first-time only)

If the user asks to set up a new GCP project or the target project doesn't exist, the setup scripts are at:
```
${AIMS_CORE_ROOT}/tools/v4/gcp-setup/
  setup_project_stage.sh      — Create GCP project, enable APIs, link billing
  setup_secrets_stage.sh      — Create secrets in Secret Manager
  setup_certificate_stage.sh  — Issue and upload SSL certificate
  setup_loadbalancer_stage.sh — Configure HTTPS load balancer for custom domain
```
Guide the user through these in order. Each script is interactive.
