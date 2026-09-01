---
name: list-audio-devices
version: 1.0.0
description: List available audio input devices and their sample-rate capabilities.
allowed-tools:
  - Bash
governance_level: green
---

# list-audio-devices

Enumerate microphones the system can see.

For each device the skill prints its index, name, channel count, and default
sample rate. This is read-only diagnostics — it changes nothing and touches no
files. Use it before recording to pick the right input.
