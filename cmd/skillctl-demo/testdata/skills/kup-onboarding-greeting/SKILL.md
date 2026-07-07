---
name: kup-onboarding-greeting
version: 0.1.0
description: Welcome a new KuP-Berlin learner with a localized greeting and orientation cues for their first session.
governance_level: green
owner: id:kup-team@kup-berlin.de
---

# kup-onboarding-greeting

A pure text-only skill that produces a short German greeting for a new
KuP-Berlin learner on their first session. No external calls, no I/O,
no subprocess.

## Inputs

- `learner_first_name` (string)
- `cohort_id` (string, e.g. `kup-2026-w19`)

## Behavior

Returns a 2–3 sentence greeting with:

1. The learner's first name.
2. The cohort id and start week.
3. A pointer to the orientation page in the platform.

## Why green

No external side-effects, no data leaves the learner's session, no
governance escalation needed. Pure templating.

## Smoke test

`tests/smoke.sh` echoes a fixed greeting for `Anna` in `kup-2026-w19`.
