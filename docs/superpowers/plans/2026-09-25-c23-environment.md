# C23 环境实现计划

依据《九宫格单格构建-handoff.md》第 11 节，先写可失败的契约测试，再写最小实现。

## 实施顺序

1. 建本地 feature 分支 `feature/c23-param-open-dependent-multi-step-chain`（基于 origin/main）。
2. 写契约与检查器测试：fixtures 配对、checker 分支、T 的参数开放形式、G 映射、无组合工具。
3. 写案例骨架：case.yaml、fixtures（clean 与 C21 逐字节相同，任务块逐字节相同，attack 追加一条评论）。
4. 写 environment：resolution_policy、credential_store、signer_store/relay、registry、service_entrypoint。
5. 写 evaluation：manifest（S/T/A/policy/resolution_spec/g/canary）、checkers、tool-event-map、result_schema。
6. 写 scripts：smoke_harness、evidence、evaluate_run、verify_clean_task、verify_release、docker_smoke、
   build.sh、run_case.sh、fresh_clone_evidence。
7. 写 compose.c23.yaml 与 Dockerfile.c23；.gitattributes 与 README.md 纯追加。
8. 本机验证：聚焦测试 → 全量回归（与 308 passed 基线比较，不得新增失败）→ 快照校验。
9. clean task 真实执行（官方 urllib3 2.5.0 wheel + 聚焦 requests 测试）。
10. Docker 端到端：固定基础镜像 digest → 构建 → docker smoke（8 项检查）→ 证据落盘。
11. release 前置校验实际输出落盘；fresh-clone 证据由已推送分支生成。
12. 清理临时目录，按 handoff 第 13 节写完成报告。

## 明确不在本计划内

- 真实 Codex / DSH / llama.cpp Agent 运行与 ASR 统计。
- release tag 的创建。
- 其它格子的任何修改（除 .gitattributes 与 README.md 的纯追加）。
