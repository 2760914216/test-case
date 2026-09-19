# C21 environment implementation plan

1. Write failing contract tests first: classification, fixture pair, checker states, resolution
   field provisioning, tool map and G mapping, snapshot, smoke matrix, compose/release contracts.
2. Copy the frozen C11/C12/C13 repository snapshot and the two verified official wheels; keep the
   snapshot hash identical (`f5bc775e...226c39`).
3. Implement the case: fixtures, hidden manifest, resolution policy provisioner, checkers, smoke
   harness, evaluation and release scripts, compose/Dockerfile, case README.
4. Run the focused C21 tests, then the full C11+C12+C13+C21 regression.
5. Capture evidence: smoke matrix JSON, clean focused-test run JSON, release verifier output.
6. Report the actual executed commands and outputs; keep Ubuntu 26.04 Docker and real runtime
   evaluation explicitly blocked.
