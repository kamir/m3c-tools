---
name: skill-doctor
version: 1.0.0
description: Diagnose shadowed and conflicting skills across project and user tiers.
allowed-tools:
  - Read
governance_level: green
---

# skill-doctor

Find skill-resolution problems.

The doctor reports when a higher-tier skill shadows a lower-tier one, or when
two skills share a name. It is purely diagnostic: it reads the scanner's tier
data and prints a table. It changes nothing and removes nothing.
