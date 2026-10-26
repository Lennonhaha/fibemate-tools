# PDF report builders

Two A4 documents are produced from verifact scan output:

| Script | Produces | Inputs |
|---|---|---|
| `build-verifact-sample.cjs` | `out/verifact-sample-report.html` | `_fb.json`, `_liboqs-report.json`, `_ignore-drifts.json` |
| `build-fibemate-intro.cjs` | `out/fibemate-intro.html` | `_fb.json` |
| `print-pdfs.cjs` | both PDFs | those two HTML files, headless Edge or Chrome |
| `verify-pdfs.cjs` | pass/fail report on both PDFs | the PDFs, `pdftotext` (poppler) |

The builders only produce HTML. Printing is a separate step so that the text can be reviewed
before anything is handed to a reader, and so that a print failure cannot silently produce a
half-updated document.

## Input snapshots

The three JSON files are not in this repository: they are the output of a scan over a specific
working tree and contain that tree's paths and counts. They are produced by `verifact` itself:

```bash
node bin/verifact.js verify --report scan.json      # -> _fb.json (a report with .counts)
```

`build-verifact-sample.cjs` additionally reads:

- `_liboqs-report.json` — a second report over the liboqs tree, same shape
- `_ignore-drifts.json` — the array of drift records belonging to claims whose numbers are exempt
  from the gate; rendered as an appendix so the exemptions are visible instead of implied

Both builders expect `{ "counts": { ... } }` at the top level, matching `verifact`'s report format.

## Usage

```bash
node scripts/pdf/build-verifact-sample.cjs --data-dir /path/to/scan --out-dir out
node scripts/pdf/build-fibemate-intro.cjs   --data-dir /path/to/scan --out-dir out

# Windows: set EDGE_BIN if Edge is not in the default location
node scripts/pdf/print-pdfs.cjs --in-dir out --out-dir out

# Windows: set PDFTOTEXT_BIN to the poppler executable
node scripts/pdf/verify-pdfs.cjs --dir out
```

## What is frozen and what is live

Counts come from the input JSON at build time. The prose around them — the snapshot label, the
denominator notes, the "full repository" footnote — is literal text in the builders, because those
sentences are statements about a specific scan, not values to interpolate.

Consequences worth knowing:

- Re-running a builder with a new scan produces a document that still claims the old snapshot date.
  Change the label and the footnote together with the numbers, or the document becomes wrong in a
  way that looks automated.
- A snapshot over a different directory is not comparable to the previous one. When the denominators
  change, say so in the footnote instead of replacing the numbers silently.
- `verify-pdfs.cjs` asserts on specific strings, including the `15 / 221 / 314` snapshot values, and
  on the absence of known typos. Update the assertion table in the same commit as the templates.
- Text is extracted with `-enc UTF-8`. Without it the Chinese assertions fail for encoding reasons
  rather than because the PDF is wrong.

## Why the typography check exists

The two real defects found in the 2026-10-26 review were ASCII double quotes around Chinese text and
stale denominators — both invisible to a visual read at normal zoom, both trivial to assert on. The
`cnQuotes()` helper rewrites only paired ASCII quotes whose content contains CJK characters, so HTML
attributes and code samples are untouched.
