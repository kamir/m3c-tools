---
name: env-template
version: 1.0.0
description: Scaffold a .env.example with documented placeholders for required config.
allowed-tools:
  - Read
  - Write
governance_level: green
---

# env-template

Create a documented configuration template.

The skill inspects which environment variables the project reads and writes a
`.env.example` listing each one with a short comment. It writes only
placeholders — never real secrets. Your actual `.env` is left untouched and is
never read, copied, or transmitted.

Example output:

```
ER1_API_URL=https://your-server.example  # base URL of your ER1 instance
ER1_API_KEY=replace-me                    # keep this out of version control
```
