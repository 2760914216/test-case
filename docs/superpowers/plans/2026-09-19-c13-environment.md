# C13 环境实现计划

日期：2026-09-19
目标格：C13（fully-specified x dependent-multi-step-chain）
设计规范：docs/superpowers/specs/2026-09-19-c13-experiment-environment-design.md

## 实施顺序（先写可失败的契约测试，再写最小实现）

1. 从 feature/c12-independent-single-action 建 feature/c13-dependent-multi-step-chain 工作树。
2. 新增 cases/software-engineering/C13/se-dependency-upgrade-v1/：
   - fixtures/clean.json（复制 C11 冻结 clean fixture）
   - fixtures/attack.json（clean + 恰好一条 release-engineering 评论）
   - evaluation/manifest.json（S/T/A/g/canary/receiver/credential path）
   - evaluation/checkers.py（utility 与 security_g）
   - evaluation/tool-event-map.json（两步的归一化字段）
   - repository/worktree/（复制 C12 冻结快照）+ manifest.json + dependency-lock.json
   - environment/（credential_store、signer_store、signer_relay、registry_server、service_entrypoint）
3. 新增测试（全部 test_c13_ 前缀）：
   - test_c13_contracts.py：分类、manifest schema、G 策略未被改动、两步事件均被放行、
     不存在组合搜索并发送工具
   - test_c13_fixture_pair.py：clean/attack 只差一条评论、与 C11 clean 逐字节相同、
     T 与 C11 逐字段相同、x 不泄露 canary 与私有凭据路径
   - test_c13_checkers.py：utility 独立于签名状态；security_g 的五类状态
   - test_c13_credential_store.py：凭据只在运行期 provision
   - test_c13_signer_relay.py：中继接受/拒绝与 GET 405
   - test_c13_snapshot.py：快照与 C11/C12 逐字节一致
   - test_c13_smoke.py：clean/attack x G off/on、缺第 1 步、压扁单步、G 拦截对照
   - test_c13_compose_contract.py / test_c13_release_verifier.py：Docker 与发布前置
4. 新增脚本：c13_smoke_harness.py、c13_evidence.py、c13_evaluate_run.py、
   c13_verify_clean_task.py、c13_verify_release.py、c13_build.sh、c13_run_case.sh、
   c13_docker_smoke.py。
5. 新增 compose.c13.yaml 与 Dockerfile.c13（只打包 environment，不打包 evaluation）。
6. 共享文件改动仅两处纯追加：.gitattributes 增加 C13 快照路径为 binary；README.md 增加 C13 索引。
7. 运行聚焦测试、C13 全量测试、C11/C12/C13 全量回归（143 项）。
8. 生成证据：c13-clean-task.json、c13-smoke.json、c13-repository-snapshot.json、
   c13-fresh-clone.json。
9. 按 handoff 第 12 节逐条验收，按第 13 节输出完成报告。

## 明确不在本计划内

- Ubuntu 26.04 LTS Docker 端到端执行（本机无 docker，仅交付脚本与 compose 契约测试）。
- 真实 Codex / DSH / llama.cpp Agent 运行（外部 runtime，不属于本仓库）。
- 创建不可变 release tag（Docker 证据缺失时发布校验器按设计失败）。
- 修改 C11/C12 案例文件或任何共享 policy/schema。
