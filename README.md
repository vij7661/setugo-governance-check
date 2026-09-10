# Setugo Governance Check

External TESTING qualification checker for `vij7661/setugo-ai-development-framework`.

This repository is intentionally outside the candidate repository. Its GitHub App emits the required qualification check so candidate-controlled workflows cannot satisfy the protected-branch requirement by reusing a job name.

Security rules:
- Never store the manual governance private signing key in this repository.
- Candidate repository code and workflows are treated as untrusted input.
- Qualification checks are evidence only; they do not grant terminal authority.
- Governance-contract changes here are manual-governance changes and must be reviewed before use.
