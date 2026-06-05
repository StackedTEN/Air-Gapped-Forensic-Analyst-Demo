# Air-Gapped Forensic Analyst — Public Demo

A **static, public demo** of the analyst GUI running against a bundled
**synthetic** incident (host `WEB-03`, case `IR-2026-031`). Click through the
product without installing anything.

This is **not** the real tool:

- **No model, no Ollama.** The Ask tab routes questions with the offline
  planner's own keyword map to answers precomputed from the real deterministic
  tools — every answer still traces to a forensic tool.
- **No real evidence, no backend.** Only the synthetic sample is bundled.
- The real, air-gapped tool runs locally with your own Ollama — the
  **"Run it on your own host"** button links to the main repo:
  https://github.com/StackedTEN/Air-Gapped-Forensic-Analyst

## Files (served as-is)

- `index.html` — the single-page console (fetches `./case.json`).
- `case.json` — precomputed case payload + per-intent planner answers.
- `generate_case.py` — regenerates `case.json` from the main repo's code.

## Deploy to Vercel

Import this repo in Vercel — **Framework Preset = Other**, no build command,
output is the repo root. It's pure static; nothing to build. Or use the CLI:

```bash
vercel
vercel --prod
```

## Local preview

```bash
python -m http.server 8099   # then open http://127.0.0.1:8099
```

## Regenerate the case (after changing the sample or tools in the main repo)

`generate_case.py` needs a checkout of the main tool repo (which has `afa/` and
`examples/`). Point it there, then commit the refreshed `case.json`:

```bash
python generate_case.py /path/to/Air-Gapped-Forensic-Analyst
# or set AFA_REPO=/path/to/Air-Gapped-Forensic-Analyst and run with no args
git add case.json && git commit -m "Refresh demo case" && git push
```

This re-derives root cause, the ATT&CK matrix, all artifact tables, and the Ask
answers from the current code, so the demo never drifts from the product.
