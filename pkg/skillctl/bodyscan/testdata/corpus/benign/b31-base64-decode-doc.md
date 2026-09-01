---
name: base64-doc
version: 1.0.0
description: Documents how to decode a base64 data URI for an embedded image.
allowed-tools:
  - Read
governance_level: green
---

# base64-doc

Reference for base64 data URIs.

A small PNG can be embedded inline as a data URI. The payload looks like a
long run of base64 such as iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAA.
There is no network call anywhere in this skill; it only formats text.
