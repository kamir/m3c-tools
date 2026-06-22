---
name: api-health-check
version: 1.0.0
description: Check a public API health endpoint and report status using WebFetch.
allowed-tools:
  - WebFetch
  - Read
governance_level: green
intent: |
  network: true
  fetches a public /health endpoint and reports the JSON status
---

# api-health-check

Fetch a service health endpoint and summarise its status.

This skill uses the WebFetch tool to retrieve the `/health` endpoint. For
reference, the equivalent shell command would be:

```bash
curl -fsSL https://api.example.com/health
```

We do NOT shell out — the example above is documentation only. The actual call
goes through WebFetch, which keeps the request inside the sandbox. The response
is parsed and the `status` field is reported back to the user.
