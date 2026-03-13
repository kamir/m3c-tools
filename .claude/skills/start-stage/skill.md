# Start Staging Environment

Start the aims-core staging service on Cloud Run to accept traffic.

## When to use

When the user says "start stage", "start staging", "wake up staging", "enable staging", or invokes `/start-stage`.

## How to execute

### Step 1: Verify current state

```bash
gcloud config set project semanpix 2>&1 | grep -v WARNING
gcloud run services describe aims-core-v4 \
  --region=europe-north1 \
  --format="value(spec.template.metadata.annotations['autoscaling.knative.dev/maxScale'])" 2>&1
```

If max-instances is already > 0, tell the user "Staging is already running" and show the URL.

### Step 2: Enable the service

```bash
gcloud run services update aims-core-v4 \
  --region=europe-north1 \
  --project=semanpix \
  --min-instances=0 \
  --max-instances=10 \
  2>&1
```

### Step 3: Verify and health check

```bash
# Wait for the update to propagate
sleep 5

# Get the service URL
SERVICE_URL=$(gcloud run services describe aims-core-v4 \
  --region=europe-north1 \
  --format='value(status.url)' 2>/dev/null)

# Health check — first request triggers cold start, may take 30-60s
curl -sk "${SERVICE_URL}/" --max-time 60 -o /dev/null -w "HTTP %{http_code} in %{time_total}s\n"
```

### Step 4: Report

Tell the user:
```
Staging is STARTED
URL: https://aims-core-v4-377906833940.europe-north1.run.app
Max instances: 10, Min instances: 0 (scales to zero when idle)
First request may take 30-60s (cold start).
```

## Important notes

- The service scales to zero when idle, so just "starting" it doesn't cost money until traffic arrives
- Cold starts take 30-60 seconds for the first request
- If the service was stopped with max-instances=0, this restores it to max-instances=10
