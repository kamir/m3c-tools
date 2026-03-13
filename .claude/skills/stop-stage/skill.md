# Stop Staging Environment

Manage the aims-core staging service lifecycle on Cloud Run.

## When to use

When the user says "stop stage", "stop staging", "shut down staging", "disable staging", "pause staging", or invokes `/stop-stage`.

## How to execute

### Step 1: Explain Cloud Run scaling

Cloud Run with `min-instances=0` (our current config) automatically scales to zero when there's no traffic. There are **no compute costs when idle**. The only ongoing costs are:
- GCR image storage (~$0.30/month)
- Secret Manager (negligible)

Tell the user this and ask what level of "stop" they want.

### Step 2: Ask what action to take

Use AskUserQuestion:

| Option | What it does | Restart effort |
|--------|-------------|----------------|
| **Leave as-is** | Service stays deployed but scales to zero. No compute cost when idle. | None — already running |
| **Delete service** | Fully removes Cloud Run service. Zero cost. | Must redeploy from scratch (~5 min) |
| **Delete service + images** | Removes service AND GCR images. Saves ~$0.30/month storage. | Must rebuild + redeploy (~15 min) |

### Step 3: Execute chosen action

**If "Leave as-is":**
```
No action needed. The service is configured with min-instances=0
and will scale to zero automatically when idle.
```

**If "Delete service":**
```bash
# Confirm first!
gcloud run services delete aims-core-v4 \
  --region=europe-north1 \
  --project=semanpix \
  --quiet
```

**If "Delete service + images":**
```bash
# Delete service
gcloud run services delete aims-core-v4 \
  --region=europe-north1 \
  --project=semanpix \
  --quiet

# Delete images (keep base images for faster rebuild)
gcloud container images delete gcr.io/semanpix/aims-core-final:latest --quiet --force-delete-tags
gcloud container images delete gcr.io/semanpix/aims-core:latest --quiet --force-delete-tags
```

### Step 4: Report

Show the user what was done and how to restart:
- Leave as-is: "Service scales to zero. Use /start-stage to verify."
- Deleted: "Service removed. Use /release-aims deploy staging to redeploy."
- Deleted + images: "Service and images removed. Use /release-aims deploy staging for full rebuild."

## Important notes

- Cloud Run min-instances=0 means NO compute cost when idle — this is already the default
- The only way to fully "stop" Cloud Run is to delete the service
- Deleting is safe: all config is captured in gcp-state.json and the deploy skill
- Base images (baseimage1-3) should be kept — they take 15+ min to rebuild
