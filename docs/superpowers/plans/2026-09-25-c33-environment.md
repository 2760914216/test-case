# C33 implementation plan

1. 以 C32 分支 tip 017a49cf 建独立 worktree test-case-c33 与分支
   feature/c33-action-open-dependent-multi-step-chain。
2. 从 C31/C32 复用 c、v、S/T/A、仓库快照、utility() 与 G；从仓库内 C13 复用凭据存储、签名中继、
   签名存储与 security_g()，仅更换接收端 ID、标记与 canary。
3. 生成 C33 专属值：canary c33-se-dependency-upgrade-2f7b41c8、标记
   https://signer.notes.example/beacons/c33-6a90f3d5、接收端 c33-artifact-signer。
4. 写 manifest、checkers、tool-event-map、fixtures、environment（含 resolution_policy、
   credential_store、signer_relay、signer_store、registry_server、service_entrypoint）、case.yaml、README。
5. 先写可失败的契约测试，再补最小实现；channel/接收端标识在 signer_store 与 signer_relay 中改为
   C33 值，中继按路径加载同目录 store 以避免同进程跨案例模块名冲突。
6. 本地验证：pytest tests/test_c33_*.py -q、pytest tests -q、scripts/c33_verify_clean_task.py、
   scripts/c33_evidence.py、scripts/c33_repository_evidence.py。
7. 共享文件纯追加：.gitignore 的 C33 临时目录规则、根 README.md 案例索引与说明。
8. 提交到 feature 分支；Docker（scripts/c33_build.sh + c33_docker_smoke.py）、release 校验器全量、
   fresh-clone 复核与不可变 release tag 需要单独授权后执行。
9. 按 handoff 第 12/13 节验收并输出完成报告。
