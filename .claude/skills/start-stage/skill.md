# Start Staging Environment

Verify or deploy the aims-core staging service on Cloud Run.

## When to use

When the user says "start stage", "start staging", "wake up staging", "enable staging", or invokes `/start-stage`.

## How to execute

### Step 1: Check if service exists

```bash
gcloud config set project semanpix 2>&1 | grep -v WARNING
gcloud run services describe aims-core-v4 \
  --region=europe-north1 \
  --format="table(status.url,spec.template.metadata.annotations['autoscaling.knative.dev/maxScale'],spec.template.spec.containers[0].image)" 2>&1
```

**If the service exists:** It's already deployed and will auto-start on the next request (cold start ~30-60s). Proceed to health check.

**If the service doesn't exist** (was deleted via /stop-stage): Tell the user to run `/release-aims deploy staging` to redeploy from scratch.

### Step 2: Health check

```bash
SERVICE_URL=$(gcloud run services describe aims-core-v4 \
  --region=europe-north1 \
  --format='value(status.url)' 2>/dev/null)

# First request triggers cold start
curl -sk "${SERVICE_URL}/" --max-time 60 -o /dev/null -w "HTTP %{http_code} in %{time_total}s\n"
```

### Step 3: Report

```
Staging is RUNNING
URL: <service URL>
Image: gcr.io/semanpix/aims-core-final:latest
Config: 2 vCPU, 4Gi, min=0, max=10
Scales to zero when idle (no cost).
```

## Important notes

- Cloud Run with min-instances=0 scales to zero automatically — "starting" just means sending a request
- Cold starts take 30-60 seconds for the first request after idle
- If the service was deleted, a full redeploy is needed via /release-aims deploy staging
