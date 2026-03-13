# Stop Staging Environment

Stop the aims-core staging service on Cloud Run to save costs.

## When to use

When the user says "stop stage", "stop staging", "shut down staging", "disable staging", "pause staging", or invokes `/stop-stage`.

## How to execute

### Step 1: Verify current state

```bash
gcloud config set project semanpix 2>&1 | grep -v WARNING
MAX=$(gcloud run services describe aims-core-v4 \
  --region=europe-north1 \
  --format="value(spec.template.metadata.annotations['autoscaling.knative.dev/maxScale'])" 2>&1)
echo "Current max-instances: ${MAX}"
```

If max-instances is already 0, tell the user "Staging is already stopped" and exit.

### Step 2: Confirm with user

Use AskUserQuestion to confirm:
```
Stop the aims-core staging service?

This will set max-instances=0, preventing any new instances from starting.
The service URL will return errors until restarted with /start-stage.
Active revision and configuration are preserved.

Proceed? (yes/no)
```

### Step 3: Stop the service

```bash
gcloud run services update aims-core-v4 \
  --region=europe-north1 \
  --project=semanpix \
  --max-instances=0 \
  2>&1
```

### Step 4: Verify

```bash
# Confirm max-instances is now 0
gcloud run services describe aims-core-v4 \
  --region=europe-north1 \
  --format="value(spec.template.metadata.annotations['autoscaling.knative.dev/maxScale'])" 2>&1
```

### Step 5: Report

Tell the user:
```
Staging is STOPPED
Service: aims-core-v4 (semanpix / europe-north1)
Max instances: 0 — no new instances will start
Config preserved — restart with /start-stage

Estimated savings: ~$0 compute while stopped
(GCR storage costs continue: ~$0.10/GB/month)
```

## Important notes

- Setting max-instances=0 prevents Cloud Run from creating any instances
- The service revision and all configuration is preserved
- Restart anytime with `/start-stage` (no rebuild needed)
- GCR storage costs (~$0.10/GB/month for ~3GB) continue regardless
- Secret Manager costs are negligible
