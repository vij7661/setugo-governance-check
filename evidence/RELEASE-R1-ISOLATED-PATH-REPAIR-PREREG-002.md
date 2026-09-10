# RELEASE R1 Isolated-Path Repair Preregistration 002

Status: FROZEN_BEFORE_REPAIR
Authority effect: NONE

Exposed checker SHA: `511af6b44cb6712e0e3559b17a5c8ffe1e351759`.
Observed RED run: `34500317723`.
Exact RELEASE candidate: `35d0b2e85e0779eb582d7968f67b06e05a5b493d`.

Frozen defect: direct `python -I <candidate-script>` execution removes the script directory from import resolution, preventing legitimate sibling imports in the candidate live-boundary verifier. A repair must not solve this by abandoning isolated mode or blindly trusting candidate import precedence.

Frozen repair contract:
1. Keep Python isolated mode for externally executed candidate paths.
2. Before adding a candidate directory to `sys.path`, reject any top-level file/package/extension whose module name collides with `sys.stdlib_module_names`.
3. Add only the exact directory required for the pinned path after stdlib modules needed by the checker-owned bootstrap are loaded.
4. Execute the pinned live-boundary verifier and pinned terminal-authority test from their intended sibling-module directories.
5. Any non-zero candidate result remains fail-closed.
6. Exact candidate/blob/App/checker bindings from RELEASE-R1-EXTERNAL-COVERAGE-PREREG-001 remain mandatory.
7. The previous RED remains preserved; no retroactive reinterpretation as PASS.
