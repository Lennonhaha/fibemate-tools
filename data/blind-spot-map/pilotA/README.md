# Pilot A — Blind-Spot Map seed corpus

## What this is

10 samples = Claude × 10 algorithm families (one neutral prompt each).
The first seed corpus that drove the Blind-Spot Map showcase page.

## `synthetic: true` — read this first

**Every sample here is synthetic seed data**, hand-written in-session to
exercise the detector pipeline and classification rubric. They are **not** an
empirical measurement of any AI system's error distribution.

## Single-AI slice

- `ai_model`: `claude`
- `model_version`: `claude-sonnet-4-20250929`
- Only model source available in the build sandbox. Measures Claude's
  systematic blind spots only; not cross-AI generality.

## Layout

```
pilotA/
  <algorithm>.json   # { algorithm, ai_model, model_version, synthetic,
                     #   human_verdict, hallucination_type, severity, note, code }
  README.md          # this file
```

License: Apache-2.0 (raw AI-generated seed code, no copyright claim).
