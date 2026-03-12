# Renew SSL Certificate (GCP Load Balancer)

Renew a Let's Encrypt SSL certificate and update the GCP HTTPS load balancer.

## When to use

When the user says "renew cert", "update certificate", "SSL expiring", "renew SSL", "cert renewal", or asks about certificate status for any deployment.

## What it does

1. **Ask** — Which deployment to renew (onboarding.guide or maindset.academy)
2. **Check** — Show current certificate expiry dates (local and live)
3. **Issue** — Run certbot/Docker to obtain a new Let's Encrypt certificate via DNS challenge
4. **Upload** — Create a new GCP SSL certificate resource
5. **Attach** — Update the target HTTPS proxy to use the new certificate
6. **Verify** — Confirm the live endpoint serves the new certificate

## Deployments

There are two deployments with separate certificates:

### Deployment 1: onboarding.guide (ER1 / aims-core legacy)

| Setting | Value |
|---------|-------|
| Domain | `onboarding.guide` + `*.onboarding.guide` |
| GCP Project | `semanpix` |
| GCP Account | `mirko.kaempf@gmail.com` |
| Target HTTPS Proxy | `my-url-map-target-proxy-2` |
| URL Map | `my-url-map` |
| Backend Service | `app-proxy-mvp-v1-0-2` |
| Cert files (local) | `/Users/kamir/GITHUB.active/my-ai-X/aims-core/sec/cert_NNN.pem` / `key_NNN.pem` |
| Cert naming pattern | `cert-YYYY-MM-NNN-o-g` (e.g., `cert-2026-03-005-o-g`) |
| DNS management | Squarespace: `account.squarespace.com/domains/managed/onboarding.guide/dns/dns-settings` |
| gcloud path | `/Users/kamir/bin/google-cloud-sdk/bin/gcloud` |

### Deployment 2: maindset.academy (Celloon / production)

| Setting | Value |
|---------|-------|
| Domain | `maindset.academy` + `*.maindset.academy` |
| GCP Account | `mirko.kaempf@gmail.com` |
| Target HTTPS Proxy | `my-url-map-ma-lb-target-proxy` |
| Cert files (local) | `/Users/kamir/GITLAB.Celloon/sec/cert_NNNN.pem` / `key_NNNN.pem` |
| Cert naming pattern | Numbered sequentially (e.g., `cert_0002.pem`) |

## How to execute

### Step 1: Ask which deployment

Use AskUserQuestion:

**"Which deployment needs a certificate renewal?"**
- `onboarding.guide` — ER1 / aims-core legacy (semanpix)
- `maindset.academy` — Celloon / production
- `Check all` — Show expiry status for all deployments

### Step 2: Check current certificate status

Check both the local cert files and the live endpoint:

```bash
# For onboarding.guide — find the highest-numbered cert:
SEC_DIR=/Users/kamir/GITHUB.active/my-ai-X/aims-core/sec
ls -la ${SEC_DIR}/cert_*.pem
openssl x509 -in ${SEC_DIR}/cert_NNN.pem -noout -subject -dates

# For maindset.academy:
openssl x509 -in /Users/kamir/GITLAB.Celloon/sec/cert_NNNN.pem -noout -subject -dates

# Check live endpoint
openssl s_client -connect <DOMAIN>:443 -servername <DOMAIN> </dev/null 2>/dev/null \
    | openssl x509 -noout -subject -dates
```

Report to the user:
- Current cert subject and expiry (local file)
- Current cert subject and expiry (live endpoint)
- Days until expiry
- Whether renewal is needed (warn if < 30 days)

If the user only asked to "check", stop here.

### Step 3: Issue new certificate with certbot

**IMPORTANT:** Claude Code cannot run `sudo` commands. Steps 3-4 require `sudo` and must be given to the user as commands to paste into their terminal. Steps 5-7 must NOT use `sudo` (gcloud needs the user's own credentials).

Give the user this command to run in their terminal:

```bash
sudo docker run -it --rm --name certbot \
    -v "/etc/letsencrypt:/etc/letsencrypt" \
    -v "/var/lib/letsencrypt:/var/lib/letsencrypt" \
    certbot/certbot \
    -d "*.${DOMAIN}" -d ${DOMAIN} \
    --manual --preferred-challenges dns certonly
```

**IMPORTANT — shell paste issue:** Multi-line commands with `\` continuations can break when pasted into zsh. If the user has trouble, provide the command as a single line or copy it to clipboard via `pbcopy`.

Tell the user:

1. Certbot will show a value for `_acme-challenge.${DOMAIN}` TXT record
2. The user must add this TXT record in their DNS provider:
   - **onboarding.guide**: Squarespace DNS settings
   - **maindset.academy**: Whatever DNS provider is used
3. Wait 1-2 minutes for DNS propagation
4. The user can verify propagation with: `dig TXT _acme-challenge.${DOMAIN}`
5. Then press Enter in the certbot prompt to complete validation

After certbot succeeds, the cert files are at:
```
/etc/letsencrypt/live/${DOMAIN}-NNNN/privkey.pem
/etc/letsencrypt/live/${DOMAIN}-NNNN/fullchain.pem
```

The `-NNNN` suffix increments with each renewal. Ask the user to check:
```bash
sudo ls -la /etc/letsencrypt/live/ | grep ${DOMAIN}
```

### Step 4: Copy cert files to local storage

**Requires sudo** — give the user these commands. Determine NEXT_NUM by checking existing files first (e.g., if highest is `cert_005.pem`, next is `006`).

```bash
# For onboarding.guide:
SEC_DIR=/Users/kamir/GITHUB.active/my-ai-X/aims-core/sec
sudo cp /etc/letsencrypt/live/onboarding.guide-NNNN/fullchain.pem ${SEC_DIR}/cert_${NEXT_NUM}.pem
sudo cp /etc/letsencrypt/live/onboarding.guide-NNNN/privkey.pem ${SEC_DIR}/key_${NEXT_NUM}.pem
sudo chown kamir:staff ${SEC_DIR}/cert_${NEXT_NUM}.pem ${SEC_DIR}/key_${NEXT_NUM}.pem

# For maindset.academy:
sudo cp /etc/letsencrypt/live/maindset.academy-NNNN/fullchain.pem /Users/kamir/GITLAB.Celloon/sec/cert_${NEXT_NUM}.pem
sudo cp /etc/letsencrypt/live/maindset.academy-NNNN/privkey.pem /Users/kamir/GITLAB.Celloon/sec/key_${NEXT_NUM}.pem
sudo chown kamir:staff /Users/kamir/GITLAB.Celloon/sec/cert_${NEXT_NUM}.pem /Users/kamir/GITLAB.Celloon/sec/key_${NEXT_NUM}.pem
```

Verify the new cert (this can run from Claude Code — no sudo needed):
```bash
openssl x509 -in <NEW_CERT_PATH> -noout -subject -dates
```

### Step 5: Generate a script for Steps 5-7

**CRITICAL: Steps 5-7 must run as the normal user (NOT sudo).** Running gcloud under sudo uses root's credentials which won't have GCP permissions.

Generate a bash script the user can run. The script should:

```bash
#!/bin/bash
set -euo pipefail

GCLOUD=/Users/kamir/bin/google-cloud-sdk/bin/gcloud
GCP_ACCOUNT="mirko.kaempf@gmail.com"
GCP_PROJECT="semanpix"
SEC_DIR=<path to sec dir>
CERT_NAME="cert-$(date +%Y-%m)-${NEXT_NUM}-o-g"  # for onboarding.guide
DOMAIN="<domain>"
PROXY="<proxy name>"  # my-url-map-target-proxy-2 or my-url-map-ma-lb-target-proxy

echo "=== Ensuring correct GCP account ==="
${GCLOUD} config set account "${GCP_ACCOUNT}"
${GCLOUD} config set project "${GCP_PROJECT}"
echo "Active account: $(${GCLOUD} config get account)"
echo "Active project: $(${GCLOUD} config get project)"
echo ""

echo "=== Step 5: Upload certificate to GCP ==="
${GCLOUD} compute ssl-certificates create "${CERT_NAME}" \
    --certificate="${SEC_DIR}/cert_${NEXT_NUM}.pem" \
    --private-key="${SEC_DIR}/key_${NEXT_NUM}.pem" \
    --description="Let's Encrypt certificate for ${DOMAIN} — $(date +%B\ %Y)"
echo ""

echo "=== Step 6: Attach to load balancer ==="
${GCLOUD} compute target-https-proxies update "${PROXY}" \
    --ssl-certificates "${CERT_NAME}"
echo ""

echo "=== Step 7: Verify live endpoint (waiting 30s for GCP propagation) ==="
sleep 30
openssl s_client -connect "${DOMAIN}:443" -servername "${DOMAIN}" </dev/null 2>/dev/null \
    | openssl x509 -noout -subject -dates

echo ""
echo "Done. Certificate ${CERT_NAME} is live on ${DOMAIN}."
```

Write this script to the sec/ directory and tell the user to run it with `bash <script>` (no sudo).

## Important notes

- **Claude Code cannot run sudo** — steps 3-4 (certbot, file copy) must be given as commands for the user to paste. Steps 5-7 (gcloud) must NOT use sudo.
- **Never mix sudo and gcloud** — running the script with `sudo bash` causes gcloud to authenticate as root, which fails with permission errors. Always run gcloud steps as the normal user.
- **DNS challenge is interactive** — the user must manually create the TXT record. This cannot be fully automated without DNS API access.
- **Shell paste issue** — multi-line commands with `\` can break in zsh. Use `pbcopy` to put single-line versions on the clipboard if the user has trouble pasting.
- **GCP propagation takes ~30s** — 10s is not enough. Use `sleep 30` before verifying the live endpoint. If still showing old cert, wait another 30s and retry.
- **certbot numbering** — Each run may create a new `-NNNN` subdirectory under `/etc/letsencrypt/live/`. Always check for the latest.
- **Use fullchain.pem not cert.pem** — GCP needs the full chain including intermediate certs.
- **Let's Encrypt rate limits** — Max 5 duplicate certificates per week per domain. Don't retry excessively.
- **Wildcard certs** require DNS-01 challenge (not HTTP-01). That's why we use `--preferred-challenges dns`.
- **gcloud path** — On this machine, gcloud is at `/Users/kamir/bin/google-cloud-sdk/bin/gcloud`, not in the default PATH.
- **Cert files contain secrets** — never log or display private key contents. Only show the cert (public) details.
- **Old certificates** in GCP are not auto-deleted. They can be cleaned up later with `gcloud compute ssl-certificates delete <old-name>`.
- **chown after sudo cp** — cert files copied with sudo are owned by root. Always chown to `kamir:staff` so they're readable without sudo.
- Let's Encrypt certs are valid for 90 days. Renew when < 30 days remain.
