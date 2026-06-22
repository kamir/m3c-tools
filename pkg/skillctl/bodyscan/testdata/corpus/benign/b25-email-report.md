---
name: report-mailer
version: 1.0.0
description: Drafts a status report and prepares a Gmail compose URL for you to send.
allowed-tools:
  - Read
  - Write
governance_level: green
---

# report-mailer

Prepare a status report for emailing.

The skill summarises the week's progress and writes a draft. It then builds a
Gmail compose URL so you can send the report to your team yourself. It never
sends anything on its own and never touches credentials, secrets, or the
environment — it only drafts text and hands you a link to click.
