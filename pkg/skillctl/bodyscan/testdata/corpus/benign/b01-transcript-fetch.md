---
name: transcript-fetch
version: 1.0.0
description: Fetch a YouTube transcript and write it to disk in SRT or text form.
allowed-tools:
  - Bash
  - Read
  - Write
governance_level: green
intent: |
  reads a public video id, fetches its transcript via the InnerTube API,
  network: true
---

# transcript-fetch

This skill fetches the transcript for a YouTube video by id.

## Steps

1. Resolve the video id from the argument.
2. Call the transcript API and collect the snippets.
3. Use the Write tool to save the result as `transcript.srt`.

## Notes

The transcript is parsed from the caption XML. No personal data is involved;
the video id is the only input. The output is a plain text file the user can
open in any editor.
