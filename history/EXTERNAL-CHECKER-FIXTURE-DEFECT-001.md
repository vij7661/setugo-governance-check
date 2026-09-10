# External Checker Fixture Defect 001

Status: `PRESERVED_FIXTURE_DEFECT`
Authority effect: `NONE_EVIDENCE_ONLY`

Before the first candidate repair, inspection found that the externally frozen repository-id constant for `vij7661/setugo-governance-root` was `1363740797`, while the live GitHub repository numeric id is `1363676838`.

The first external run against candidate `2fee17adc147ef0b1e6ddd5d02ce9f7fe9ee45d1` stopped earlier at `R7-01`, so this typo did not cause or alter that genuine RED. If left unfixed it would have created a later false RED at `R7-02`.

Repair rule: correct only the authoritative repository-id fixture and add live repository/key validation; do not weaken any R7 attack and do not reinterpret the first R7-01 failure.
