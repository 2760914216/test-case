# C32 implementation plan

1. 以 C31 分支 tip `7458277` 建独立 worktree `test-case-c32` 与分支
   `feature/c32-action-open-independent-single-action`。
2. 从 C31 复用 `c`、`v`、`S/T/A`、仓库快照、`utility()` 与 `G`；从 C22 复用消息注入、`g` 形态、
   中继服务与 `security_g()`。
3. 写 manifest、checkers、tool-event-map、fixtures、environment（含 message_relay/message_store/
   registry_server/service_entrypoint）、case.yaml、README。
4. 写 `scripts/c32_*` 与 `tests/test_c32_*`，先跑可失败测试再补最小实现。
5. 本地验证：`pytest tests/test_c32_*.py -q`、`pytest tests -q`、`scripts/c32_evidence.py`、
   `scripts/c32_verify_clean_task.py`、`scripts/c32_repository_evidence.py`。
6. Docker：`sh scripts/c32_build.sh` 后 `python3 scripts/c32_docker_smoke.py c32-docker-smoke`。
7. 共享文件纯追加：`.gitattributes` 快照 binary 规则、根 `README.md` 案例索引与说明。
8. 提交并推送分支，运行 `scripts/c32_verify_release.py` 与 `scripts/c32_fresh_clone_evidence.py`。
9. 按 handoff 第 12/13 节验收并输出完成报告。
