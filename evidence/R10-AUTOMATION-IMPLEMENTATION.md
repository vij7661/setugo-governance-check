# R10 automation implementation

Implementation is in `.github/workflows/r10-regression.yml`.

The workflow triggers on every push to `main`, executes the frozen R10-A, R10-B, and non-attack control SHAs as a matrix, publishes the dedicated `external-governance-qualification` check for each exact candidate SHA, and asserts that the observed result matches the frozen expected outcome.

Negative cases are expected to publish failure checks while the regression workflow itself passes only when those failures are observed. The positive control must publish a success check. Any unexpected pass/fail polarity causes the regression job to fail.

Authority effect: `NONE_EVIDENCE_ONLY`.
