# RELEASE R1 External Isolated-Path RED 001

Status: PRESERVED_RED
Authority effect: NONE

Exact checker candidate: `511af6b44cb6712e0e3559b17a5c8ffe1e351759`.
Exact RELEASE candidate: `35d0b2e85e0779eb582d7968f67b06e05a5b493d`.
Workflow run: `34500317723`.
Observed result: FAILURE.

The base externally pinned qualification corpus completed successfully, including 112 isolated tests and the RELEASE bridge-shape regressions. The added REL-R1-03 execution then attempted to run `governance-runtime/verify_external_trust_root_control.py` with `python -I <absolute-script>`. Python isolated mode intentionally removed the candidate script directory from import search, so the script could not import sibling `external_governance_root` and failed with `ModuleNotFoundError`.

This is a RELEASE qualification harness integration defect, not evidence that the candidate live-boundary logic failed. The failure remains preserved and no PASS is inferred.
