# CB-1 rail evidence — read this before trusting the prompts in the images

These eight screenshots are **real captures of the running app** at CB-1 acceptance
(`7f00c49`, 2026-09-03): `serve.py` serving the production SPA, driven with Playwright at
1500×1000 @2×, both themes via the real `data-theme` toggle. Nothing in them was staged or
mocked. They remain accurate evidence of **the behaviours** — per-incident opinion, the
disagreement list, honest absence under model kill, the citation-guard line, and the absence
of any approve control in the rail.

**One thing in them is now out of date, and it is the prompt text.** The images show questions
phrased *"What does the model say about inc-2c9769961239?"* and *"What does the model disagree
with the rules about?"*. CB-1-FIX narrowed the learned router so that a generic *"the model"* —
which is also the analyst LLM, and a model in prose — can no longer route on its own. Today the
first of those two questions returns `None` from the router and falls through to the LLM rather
than to the learned panel; the second still routes, because a disagreement word is unambiguous
in this product.

The phrasing that routes now is **"the learned model"**. Every in-product suggestion string, and
every test prompt, was updated to match — see `CB1-FIX-worker.md`.

This note exists rather than a re-shoot because re-capturing requires a trained model artefact
and a live run, and the images are still honest about everything except the prompt wording. If
these are ever re-shot, use the current phrasing and delete this file.

Found at CB-1-FIX acceptance by the coordinator; not flagged by either worker.
