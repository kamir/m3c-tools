# Distill contract (SPEC-0269 P1) — article-analyzer

You are the **article-analyzer**. Your task names ONE wave + batch (e.g. "wave 2, batch w2b07").
Let `WAVE` = the wave dir (e.g. `w2`) and `BID` = the batch id (e.g. `w2b07`). Base dir:

    B = /Users/kamir/GITHUB.kamir/mirkos-braindump/.understand-anything/waves/<WAVE>

## Steps

1. Read `B/batch-<BID>.json` — a JSON array of `{id, path, name}` (your articles).
   Read `B/allids.json` — every valid article id in the corpus. Use these EXACT ids as edge
   `source`/`target`; never invent an article id.
2. For each item, **Read** its `path` — a personal voice-memo / field-note: YAML frontmatter
   (id, date, tags, a `transcript_text`/body) then content, German or English (mixed). The
   substance is the transcript/body.
3. **WRITE** `B/out/analysis-<BID>.json`:
   ```json
   {"nodes":[
      {"id":"entity:<kebab-name>","type":"entity","name":"Proper Name","summary":"one line","tags":["entity"],"complexity":"simple"},
      {"id":"claim:<article-stem>:<slug>","type":"claim","name":"short title","summary":"the assertion, 1-2 sentences","tags":["claim"],"complexity":"simple"}
   ],"edges":[
      {"source":"article:...","target":"article:...|entity:...|claim:...","type":"builds_on|contradicts|exemplifies|authored_by|cites","direction":"forward","weight":0.8,"description":"brief textual evidence"}
   ]}
   ```
   Rules: **entities** = named people/tools/orgs/products NOT already an article. **claims** =
   the note's assertions/decisions/theses. **edges** ONLY with clear textual evidence
   (builds_on 0.8, contradicts 0.9, exemplifies 0.7, authored_by 0.6, cites 0.7). Cross-article
   edges among corpus articles where notes genuinely connect are encouraged. Dedupe entities.
   Be conservative. Do NOT output article or topic nodes.
4. **WRITE** `B/out/distilled-<BID>.json`:
   ```json
   [{"id":"article:...","title":"inferred human title (NOT a timestamp)","summary":"2-3 sentence English gist","key_points":["..."],"entities":["..."],"claims":["..."],"lang":"de|en"}]
   ```
   Each distilled `id` MUST equal its batch item's `id`.
5. Return as your FINAL message ONLY: `{"batch":"<BID>","articles":N,"entities":N,"claims":N,"edges":N}`
