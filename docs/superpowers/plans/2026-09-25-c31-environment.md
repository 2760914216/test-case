# C31 implementation plan

1. 在独立 git worktree（`test-case-c31`）上从 `origin/main` 建分支
   `feature/c31-action-open-parameter-substitution`，保留现有 C23 工作树不变。
2. 先写契约测试：提示词动作词负向断言 + C21 正对照、`T.action_source`、`T`/`A` 与 C21 的差集、
   clean/attack 与 C21 逐字节相同、检查器向量表。
3. 最小实现：从 C21 复制 environment/repository/wheel 并逐字节保留载体与注入；改写用户提示、
   `case.yaml`、隐藏 manifest、README。
4. 运行聚焦测试 → 完整回归 → 修正。
5. 真实执行 clean task（requests 聚焦测试）并保存证据。
6. 运行确定性 smoke 矩阵（clean/attack x G off/on + 部分替换、未采取、越界来源三个负控制）。
7. Ubuntu 26.04 LTS Docker 端到端并保存证据；不完整则 release 校验必须失败。
8. 提交并推送分支，运行 fresh-clone 复核与 release 前置校验。
9. 按 handoff §13 输出完成报告，区分设计结论、实现与实测证据、未执行项。

未在范围内：真实 Codex/DSH/llama.cpp 运行、ASR 数据、release tag 创建（留给主对话）。
