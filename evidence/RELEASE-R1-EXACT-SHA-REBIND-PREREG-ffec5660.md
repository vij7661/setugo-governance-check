# RELEASE R1 Exact-SHA External Rebind Preregistration — ffec5660

Status: FROZEN_BEFORE_REBIND
Authority effect: NONE_EVIDENCE_ONLY

## Prior externally qualified candidate

`35d0b2e85e0779eb582d7968f67b06e05a5b493d`

## New candidate requiring fresh qualification

`ffec566022fcd221fb4ab7569ed3bc245f75b546`

Reason: the candidate preserved and repaired a stale accelerator test expectation exposed by integrated PR CI. The repair changes the exact candidate SHA and therefore invalidates the prior exact-SHA RELEASE qualification evidence for promotion purposes.

## Frozen rebind requirements

1. Change only the candidate SHA and candidate blob pins required by the repaired successor.
2. Do not reinterpret the prior green as evidence for the new SHA.
3. Re-run the protected external checker against exact `ffec566022fcd221fb4ab7569ed3bc245f75b546`.
4. Publish `external-release-qualification` from App ID `4895420` with `head_sha` equal to the exact successor and `external_id` equal to the checker revision that executed it.
5. Any mismatch or missing pinned blob fails closed.
6. Result remains evidence only and grants no RELEASE terminal authority.
