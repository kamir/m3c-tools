---
name: kup-hello
version: 0.1.0
governance_level: yellow
owner: id:mirko@m3c
human_checkpoints: ["confirm-output"]
context_scope: ["fs:write:<cwd>/output/**"]
---

# kup-hello

Demo skill for the KuP Skill-Manager training session. Writes a single
`hello.txt` to `./output/` to demonstrate the chain end-to-end:

  Author signs → Registry counter-signs → Reviewer attests →
  Eric pulls and verifies → Eric runs (envelope-bounded).

The skill itself is intentionally trivial. The point is that every
byte travelled through a signed chain.

## Usage

Run the helper:

```
./scripts/hello.sh
```

It writes `output/hello.txt` and prints the canonical KuP greeting.
