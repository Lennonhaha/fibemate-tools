# Pilot B — Blind-Spot Map seed corpus

## What this is

30 samples = Claude × 10 algorithm families × 3 prompt variants.
Each algorithm file contains a `variants` array (v1/v2/v3), all generated
from **neutral** prompts (no words like secure / constant-time / correct /
"you are writing a crypto library"). All three variants require the code to
actually run in Node.js.

## `synthetic: true` — read this first

**Every sample here is synthetic seed data.** They were hand-written to
exercise the detector pipeline and the classification rubric. They are
**not** an empirical measurement of any AI system's error distribution.

A real measurement requires independently generated samples across multiple
models — see `ANALYSIS.md` for the methodological boundary.

## Single-AI slice

- `ai_model`: `claude`
- `model_version`: `claude-sonnet-4-20250929`
- This is the only model source available in the build sandbox (no GPT/Gemini
  key or egress). It measures Claude's systematic blind spots only; it does
  NOT represent cross-AI generality.

## Variant analysis = detector stability, NOT blind-spot expansion

Pilot B's three variants per algorithm are **not** meant to widen the
blind-spot matrix. They test whether the same AI, given differently-worded
but semantically neutral prompts for the same algorithm, produces the *same*
hallucination class. Where the class is stable across variants, the
blind spot is a property of the AI's capability, not prompt wording.

See `ANALYSIS.md` for the per-algorithm stability finding.

## File layout

```
pilotB/
  <algorithm>.json   # { algorithm, ai_model, model_version, synthetic,
                     #   human_verdict, hallucination_type, severity, note,
                     #   variant_count, variants: [v1, v2, v3] }
  README.md          # this file
  ANALYSIS.md        # variant stability findings + methodology boundary
```

License: Apache-2.0 (raw AI-generated seed code, no copyright claim).
