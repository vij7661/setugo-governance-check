# R11 Candidate-Head Automated Qualification Preregistration

Status: FROZEN_BEFORE_AUTOMATED_QUALIFICATION
Authority effect: NONE_EVIDENCE_ONLY

Candidate PR #33 exact head to qualify before merge:
`72b53625a2a5cc9498a7455203b3028cedf86505`

Current authoritative candidate base:
`bb6c8adc3ba98b2e9b06ba65d10ef36a061b2ceb`

Current checker base before this automation update:
`e903294a1e82e4caf6ef3ce23f2d1b0e9070647c`

Frozen expectation:
- R10-A attack remains FAILURE.
- R10-B attack remains FAILURE.
- R11 candidate PR head `72b53625...` must PASS under the exact merged checker revision that contains this vector.
- The emitted `external-governance-qualification` check must have head_sha exactly `72b53625...` and external_id exactly equal to that merged checker SHA.
- A later merge of candidate PR #33 will create a different successor SHA and must receive fresh exact-SHA qualification; this pre-merge result cannot be replayed for that successor.

The workflow/check remains evidence only and grants no TESTING, RELEASE, or PRODUCTION authority.
