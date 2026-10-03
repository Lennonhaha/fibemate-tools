# Minimal CycloneDX 1.6 regression controls

These are standalone, fully synthetic schema-validation fixtures, not scanner output or a full CBOM conformance suite.

| File | Expected result | Observed CLI exit code |
|---|---|---|
| valid-sha256.json | Valid | 0 |
| invalid-uppercase-primitive.json | Invalid: case-sensitive primitive enum | 1 |
| invalid-misplaced-field.json | Invalid: additional property under cryptoProperties | 1 |

Each invalid fixture differs from the valid control by exactly one mutation.

Validated offline with CycloneDX CLI 0.33.1. From this directory, substitute each filename:

```sh
cyclonedx validate --input-file valid-sha256.json --input-format json --input-version v1_6 --fail-on-errors
```

Repeat with the two invalid filenames and assert nonzero exit codes. A validator launch or infrastructure failure must not count as successful rejection: check the validation diagnostic as well. Schema validity does not establish semantic completeness, security, certification, or cryptographic correctness.

No package installation, keys, production data, repository credentials or private suite code is included.
