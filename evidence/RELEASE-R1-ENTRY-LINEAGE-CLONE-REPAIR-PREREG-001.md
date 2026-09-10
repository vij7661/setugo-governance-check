# RELEASE R1 Entry-Lineage Clone Repair Preregistration — 001

Status: FROZEN_BEFORE_REPAIR
Authority effect: NONE_EVIDENCE_ONLY

## Exposed defect

Checker revision `393cdf062bc41fc21073ed2742ad6eb82a566efe` failed in workflow run `34502337103` before lineage evaluation because the Git clone authentication transport was malformed for the candidate repository clone.

## Allowed repair

The candidate repository is public. Remove only the unnecessary custom Git HTTP authentication flags from the clone/fetch used for ancestry proof. Preserve all exact source/candidate SHA assertions, source qualification, ancestry proof, App-bound publication, protected-main requirement, and fail-closed behavior.

The repaired run must still prove:

- source `15d50cc25ae524fc64e2c65269c91135e0361846` is qualified by the frozen RELEASE-entry checker;
- candidate `ffec566022fcd221fb4ab7569ed3bc245f75b546` is checked out exactly;
- source is an ancestor of candidate;
- `external-release-entry-qualification` is published on the candidate SHA by App ID `4895420` with checker revision in `external_id`.

No authority is granted by a green result.
