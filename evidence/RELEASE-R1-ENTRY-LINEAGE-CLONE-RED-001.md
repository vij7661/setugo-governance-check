# RELEASE R1 Entry-Lineage Clone RED — 001

Status: PRESERVED_RED
Authority effect: NONE_EVIDENCE_ONLY

## Exact checker revision

`393cdf062bc41fc21073ed2742ad6eb82a566efe`

## Candidate

`ffec566022fcd221fb4ab7569ed3bc245f75b546`

## Failing evidence

Workflow run `34502337103` failed after the frozen RELEASE-entry checker itself returned `PASS_BOUNDED_EVIDENCE_ONLY` for source SHA `15d50cc25ae524fc64e2c65269c91135e0361846`.

The new lineage step then failed before ancestry evaluation with:

`fatal: could not read Username for 'https://github.com': No such device or address`

The failure was caused by the newly added Git clone authentication invocation, not by a failed ancestry assertion.

## Classification

CHECKER_HARNESS / AUTHENTICATION_TRANSPORT_DEFECT.

This RED is preserved before repair. A later green cannot erase it.
