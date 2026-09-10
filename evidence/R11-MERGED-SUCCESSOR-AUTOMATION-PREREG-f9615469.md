# R11 Merged-Successor Automated Qualification Preregistration

Status: FROZEN_BEFORE_AUTOMATED_QUALIFICATION
Authority effect: NONE_EVIDENCE_ONLY

Exact merged candidate successor:
`f9615469a2faea8696950974de2182972edf81bf`

Parent candidate PR head:
`72b53625a2a5cc9498a7455203b3028cedf86505`

Current checker base before this vector update:
`6f5c7d884d6643c33662a78b677ad05b0ea81f34`

Frozen expectation:
- R10-A attack remains FAILURE.
- R10-B attack remains FAILURE.
- Exact merged successor `f9615469...` must PASS under the exact merged checker revision containing this vector.
- The emitted App check must bind head_sha exactly to `f9615469...` and external_id exactly to that checker revision.
- The earlier successful check on PR head `72b53625...` is not sufficient for this successor and must not be replayed.

This is qualification evidence only and grants no TESTING, RELEASE, or PRODUCTION authority.
