# RELEASE Falsification Review — v16 COMPLETE CURRENT INTEGRATION

**Overall Disposition: PASS**

The v16 packet directly cures the v15 packet-completeness residuals. All four F-02 sub-findings that v15 classified as `PARTIALLY_CLOSED` solely because their integration sources were not embedded are now closed at bundle level: the integrated launcher shows the working-tree verification call site, the fd-based OpenSSL operand handoff is fully wired with `/proc/self/fd/<fd>` and `pass_fds`, the seccomp profile JSON is embedded, the post-bootstrap libseccomp `execve`/`execveat` denial source is shown and is installed before the base runtime guard, and the `_NoRedirect` host proxy with `geturl()` equality check is fully integrated. The three observations the v15 review classified as optional (`.gitattributes` clean/smudge false-positive direction, `release.r10` module-identity robustness, seccomp denylist breadth) remain non-blocking under the reviewer instruction — none of them is a concrete false-green path.

All prior results are preserved exactly: pre-ruleset RED `attempt 1`, v2/v3/v4 `INSUFFICIENT_EVIDENCE`, v5–v15 `BOUNDED_PASS`, the v9 capability-guard REDs A/B, the `daee2aa…` blanket-process RED, the `34569365671` bootstrap RED, the `34569523852` REST HTTPError RED, the `c622a416…` OpenSSL text-mode RED, PR #44 (closed unmerged), the v14 PR #45 Docker UID/GID and trusted-`ctypes` smoke REDs, the protected-main networkless governance-root RED `34577634345`, PR #47 R11 fixture RED, the protected-main standalone R10 regression RED `34582590283`, PR #48 (closed unmerged), and PR #49 / current checker `6ced9049…`.

---

## Independent verification status

| Fact | Status |
|---|---|
| Candidate SHA `4200397f…` | BUNDLE_VERIFIED |
| Current protected checker `6ced9049…` | BUNDLE_VERIFIED |
| `run_candidate_unittests_sandboxed.py` (blob `975f3be7…`) | BUNDLE_VERIFIED |
| `run_candidate_unittests_sandboxed_v2.py` (blob `2e13a0d3…`) | BUNDLE_VERIFIED |
| `run_candidate_unittests_isolated_v3.py` (blob `f28fb7d2…`) | BUNDLE_VERIFIED |
| `run_candidate_unittests_isolated_v4.py` (blob `d39659e9…`) | BUNDLE_VERIFIED |
| `seccomp-release-sandbox.json` (blob `682a6881…`) | BUNDLE_VERIFIED |
| `test_release_f02_external_sandbox.py` (blob `88b43abd…`) | BUNDLE_VERIFIED |
| `test_release_f02_v14_hardening.py` (blob `00a21e90…`) | BUNDLE_VERIFIED |
| `.github/workflows/r11-checker-selftest.yml` (blob `40ba9c4d…`) | BUNDLE_VERIFIED |
| Protected-main runs `34585586326` / job `103218924889` | LIVE_VERIFICATION_UNAVAILABLE |
| Exact-candidate check runs `103218971100`, `103219085870`, `103218955556`, `103218954763` | LIVE_VERIFICATION_UNAVAILABLE |
| Docker image digest `python@sha256:581429e3…` | Assumed pinned |
| Live ruleset `22789078` and App identity `4895420` | LIVE_VERIFICATION_UNAVAILABLE |

---

## F-01 — Live external governance/root verification

**Status: CLOSED (inherited from v7)**
**Severity: Critical**

No change. V2 `SETUGO_REVIEW_ADJUDICATION_ED25519_V2` binding, `validate_root_metadata()` per-field equality, and scope/class/decision/phase/effect rebinding negative controls remain fully shown.

---

## F-02 — Full qualification runtime closure

**Status: CLOSED**
**Severity: Critical**

### F-02-a — Working tree vs HEAD binding

**Status: CLOSED**

- The integrated launcher's `main()` shows the sequence: `_decode_manifest`, then `_validate_manifest(candidate_root, manifest)`, then `_verify_working_tree_matches_manifest(candidate_root, manifest)`, then sandbox creation. All three precede `docker run`.
- `_verify_working_tree_matches_manifest` runs `git update-index -q --refresh`, `git diff-index --quiet HEAD --`, and per-path `git hash-object -- <relpath>` against the manifest SHA. The `diff-index` gate is the load-bearing worktree-vs-HEAD check; the per-path check is defense-in-depth.
- Concrete failure paths: none — the integration matches the v15 description and the source is shown.

### F-02-b — fd-based OpenSSL operand handoff

**Status: CLOSED**

- `_operand_parts` requires the value to literally start with `/sandbox-io/` and rejects any path whose parts contain `..`. `_open_operand_fd` walks each intermediate component with `O_RDONLY | O_DIRECTORY | O_NOFOLLOW`, then opens the leaf with `O_NOFOLLOW` plus either `O_RDONLY` (input) or `O_WRONLY | O_CREAT | O_TRUNC` (output), anchored by `dir_fd`. `os.fstat(fd)` is required to be `S_ISREG`; otherwise the fd is closed and the call returns `None`.
- `_prepare_openssl_argv` rewrites input/output operands to `/proc/self/fd/<fd>` and returns the tuple of fds.
- Both `_serve_helper` (base launcher) and `_serve_helper_v2` (proxy successor) call `_prepare_openssl_argv`, run OpenSSL via `subprocess.run(..., pass_fds=fds)`, and close all fds in a `finally` block.
- Concrete failure paths: none — the fd handoff is complete, path-swap between validation and open is closed by the fd model, symlink components at any depth are rejected by `O_NOFOLLOW`, and the output leaf is created with `O_CREAT | O_TRUNC` under `host_io`.

### F-02-c — Two-stage seccomp

**Status: CLOSED**

- The Docker command now includes `--security-opt seccomp=<SECCOMP_PROFILE>`, where `SECCOMP_PROFILE = CHECKER_DIR / "seccomp-release-sandbox.json"` and `_build_docker_cmd` raises `RuntimeError("RELEASE sandbox seccomp profile missing")` if the file is absent.
- The profile JSON is embedded. It denies `clone`, `clone3`, `fork`, `vfork`, `unshare`, `setns`, `ptrace`, `bpf`, `mount`, `umount2`, `pivot_root`, `chroot`, `kexec_load`, `kexec_file_load`, `init_module`, `finit_module`, `delete_module` — with `SCMP_ACT_ERRNO`. `execve`/`execveat` are deliberately not in the pre-start denylist so Docker can bootstrap the Python entrypoint.
- `run_candidate_unittests_isolated_v3.py` embeds `_install_kernel_exec_seccomp()`, which loads libseccomp, resolves `execve` and `execveat`, adds `SCMP_ACT_ERRNO | EPERM` rules, and calls `seccomp_load`. It then probes with `os.execve` against a path that cannot exist under `--read-only`, treating `PermissionError` as the success marker (`F02_RUNTIME_SECCOMP execve=denied`) and `FileNotFoundError` as evidence that the filter did not activate (which raises `RuntimeError`).
- `_install_runtime_guard_v3` calls `_install_kernel_exec_seccomp()` **before** `_original_install_runtime_guard`, i.e., before the audit hooks are installed and before any candidate module is imported. Ordering is correct.
- The v14 hardening regression source is embedded: `test_seccomp_is_two_stage_and_explicit` asserts one `seccomp=` argument is present, checks the profile contains the intended denials and not `execve`/`execveat`, and asserts the source of `_install_kernel_exec_seccomp` is invoked before `_original_install_runtime_guard` in `_install_runtime_guard_v3`.
- The real-Docker smoke test (`test_real_docker_sandbox_smoke`) requires the `F02_RUNTIME_SECCOMP execve=denied` marker in stdout.
- The R11 workflow executes both test files and `verify_release_runtime_import_closure.py`.
- Concrete failure paths: none demonstrated. Informational note — the pre-start profile is a denylist (`SCMP_ACT_ALLOW` default) rather than a syscall allowlist. This is a defense-in-depth reduction in kernel attack surface relative to Docker's default seccomp profile, but with `--cap-drop ALL`, `--no-new-privileges`, `--network none`, `--read-on��="24blocking

- **`.gitattributes` clean/smudge and `git hash-object`.** As previously noted, `git hash-object -- <path>` hashes raw file bytes; if a path-attribute clean filter is defined, the working-tree bytes differ from the HEAD blob and the check would reject a legitimate file. The failure direction is over-rejection (false-red), not false-green, so this is not a blocking finding under the reviewer instruction.
- **`release.r10` module-identity.** The release wrapper writes `release.r10.REQUIRE_EXTERNAL_SANDBOX = True` and `release.r10.RUNTIME_PINNED_BLOBS = ...` via attribute mutation on the `falsify_candidate_r10_entry` module. In the standard import path this is the same module object the R10 entry reads. A future refactor that reimports that module under a different name could break the coupling, but no such refactor exists today, and no false-green path is shown. Not blocking.
- **Post-bootstrap seccomp probe path.** The probe uses `/__setugo_execve_probe_must_not_exist__`. In a read-only rootfs this path cannot exist. If somehow the probe path existed and were executable, the pre-seccomp code would execve it and replace the process. This is a theoretical edge case; the path is not creatable under `--read-only` and does not exist in the digest-pinned base image. Not blocking.

---

## F-03 — Silent zero-test execution

**Status: CLOSED (inherited from v5)**
**Severity: High**

No change.

---

## F-04 — Committed bytecode/cache shadowing

**Status: CLOSED (inherited from v5)**
**Severity: High**

No change.

---

## F-05 — Immutable third-party Action pinning

**Status: CLOSED (inherited from v5)**
**Severity: High**

No change.

---

## F-06 — Independent policy-hash recomputation

**Status: CLOSED (inherited from v5)**
**Severity: Critical**

No change.

---

## F-07 — Live RELEASE ruleset enforcement

**Status: CLOSED (bundle) / `LIVE_VERIFICATION_UNAVAILABLE`**
**Severity: Critical**

- **Embedded evidence inspected:** Current packet claims ruleset `22789078` remains active on `refs/heads/phase/release`, with `bypass_actors = []`, `current_user_can_bypass = "never"`, strict required checks, and all four contexts bound to `integration_id 4895420`. It cites protected-main run `34585586326` (job `103218924889`) as SUCCESS and lists the current exact-candidate App check runs.
- **Adversarial note:** No API transcript with ETag is embedded; the reviewer environment cannot independently re-witness the live endpoint. `LIVE_VERIFICATION_UNAVAILABLE` remains the correct separate classification.
- **Fail-closed posture:** `external-release-review-adjudication` and `external-release-merge-authority` remain FAILURE on the exact candidate, which is the required posture in the absence of a signed independent PASS adjudication and a digest-bound `HUMAN_RELEASE_AUTHORITY`. A SUCCESS in that state would be a Critical false-green; the packet shows none.

---

## F-08 — Independent adjudication prerequisite and digest-bound terminal authority

**Status: CLOSED (inherited from v5)**
**Severity: Critical**

No change. The v16 packet does not touch the F-08 pipeline.

---

## Additional adversarial vectors (v16 delta)

- **Working-tree verification call site** — confirmed in the integrated launcher's `main()`.
- **fd-based OpenSSL handoff** — confirmed end-to-end: `_prepare_openssl_argv` → `_open_operand_fd` → `pass_fds` → `finally: os.close(fd)` in both the base launcher helper and the v2 proxy helper.
- **Two-stage seccomp** — confirmed: pre-start profile embedded and applied via `--security-opt seccomp=`, post-bootstrap libseccomp filter installed before any candidate import, marker required by the Docker smoke test.
- **Governance-root redirect** — confirmed: `_NoRedirect` + `geturl()` equality check, plus a regression test.
- **RELEASE sandbox wiring** — unchanged from v15; still forces `REQUIRE_EXTERNAL_SANDBOX = True` and requires a non-empty pin union.
- **Seccomp denylist breadth** — flagged as an informational defense-in-depth observation; no candidate-varying false-green path demonstrated.
- **`_NoRedirect` HTTPError path** — the handler returning `None` results in urllib raising `HTTPError`, which `_host_fetch` catches and converts to `RuntimeError`, causing the container request to fail closed. The `geturl()` equality check is a redundant defense.
- **`_operand_parts` normalization** — Path normalizes `.` components; `..` components are explicitly rejected. No path-escape vector demonstrated.
- **`_install_kernel_exec_seccomp` ordering** — invoked first in `_install_runtime_guard_v3`, before the base runtime guard is installed and before candidate imports. Correct.

---

## Prior history preservation

All prior outcomes remain preserved and un-downgraded:

- Pre-ruleset RED `attempt 1`.
- v2/v3/v4 `INSUFFICIENT_EVIDENCE`.
- v5–v15 `BOUNDED_PASS`.
- v9 capability-guard REDs A/B.
- `daee2aa…` blanket-process RED.
- PR #40 bootstrap RED `34569365671`.
- Protected-main REST HTTPError RED `34569523852`.
- v11 `BOUNDED_PASS`.
- Protected-main `c622a416…` OpenSSL text-mode RED.
- v12 `BOUNDED_PASS` / F-02 `PARTIALLY_CLOSED`.
- PR #44 closed unmerged.
- v14 PR #45 Docker smoke REDs (UID/GID mismatch; trusted-`ctypes` ordering). Both repaired without policy weakening.
- Protected-main `250fcd6f…` R1 `34577634345` networkless governance-root RED. Repaired by host proxy in PR #46 without restoring candidate network.
- PR #47 merged as `eb964b17…`; R11 fixture RED preserved.
- Protected-main standalone R10 regression RED `34582590283`.
- PR #48 closed unmerged.
- PR #49 merged as current protected checker `6ced9049…`.
- Protected-main R1 `34585586326`: SUCCESS (asserted).
- Current fail-closed state on `external-release-review-adjudication` and `external-release-merge-authority`: preserved.

---

## Summary classification of F-01 … F-08

| Finding | Status |
|---|---|
| F-01 | CLOSED |
| F-02 | CLOSED |
| F-03 | CLOSED |
| F-04 | CLOSED |
| F-05 | CLOSED |
| F-06 | CLOSED |
| F-07 | CLOSED (bundle) / `LIVE_VERIFICATION_UNAVAILABLE` |
| F-08 | CLOSED |

---

## Why PASS and not BOUNDED_PASS

The v15 review identified exactly four packet-completeness residuals (F-02-a through F-02-d integration sources not embedded) and stated that embedding them would move F-02 to `CLOSED` at bundle level and the overall disposition to `PASS`, with F-07 remaining `LIVE_VERIFICATION_UNAVAILABLE`. All four are now embedded and verified. F-02-e was already `CLOSED` in v15. F-01, F-03, F-04, F-05, F-06, and F-08 were `CLOSED` in prior packets and unchanged. The three optional observations (`.gitattributes` false-positive direction, `release.r10` module identity, seccomp denylist breadth) do not constitute false-green paths, and the reviewer instruction explicitly directs against promoting them into blocking findings absent such a path. No candidate-varying false-green mechanism has been identified.

---

## Authority restriction

This result is `AUTHORITY_EFFECT = NONE_EVIDENCE_ONLY`. It does not issue `HUMAN_RELEASE_AUTHORITY`. It does not authorize or perform merge. The release candidate remains blocked until a separate authorized human terminal decision is produced and cryptographically bound to this adjudication's digest.

**The release candidate must remain blocked pending separate human release authority.**