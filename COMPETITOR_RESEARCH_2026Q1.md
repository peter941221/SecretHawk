# SecretHawk 竞品调研与强化空间（2026-02-26）

## 1) 调研范围

- GitHub Secret Protection
- GitGuardian (平台 + ggshield)
- TruffleHog OSS
- Gitleaks
- detect-secrets

## 2) 竞品能力矩阵

| 维度 | GitHub Secret Protection | GitGuardian | TruffleHog | Gitleaks | detect-secrets | SecretHawk 当前 |
|---|---|---|---|---|---|---|
| 检测（Detection） | 强（GitHub原生） | 强（平台+CLI） | 强（多源） | 强（Git/dir） | 中（以baseline为核心） | 中（规则已扩展） |
| 有效性验证（Validation） | 有（部分类型 validity checks） | 有（Valid/Invalid） | 强（verified/unverified/unknown） | 弱（以检测为主） | 中（可 only-verified） | 中（connector骨架） |
| 自动撤销/轮转（Revoke/Rotate） | 以流程指引为主 | 强（支持部分provider直接撤销） | 弱（偏验证） | 弱 | 弱 | 弱到中（骨架+手动指引） |
| 开发者阻断（Prevention） | 强（push protection + delegated bypass） | 强（pre-commit/pre-push + message） | 中（--fail + hooks） | 中（pre-commit/action） | 中（hook+baseline） | 中（hook/CI已具备） |
| 修复编排（Remediation Orchestration） | 流程指引完善 | 强（workflow/playbooks） | 中 | 弱 | 弱 | 中（remediate/patch/report） |
| 历史清理（History Clean） | 指南导向 | 指南导向 | 间接支持 | 间接支持 | 无 | 中（有门禁） |
| 报告与治理（Reporting/Governance） | 强（审计/告警） | 强（incident流程） | 中 | 中（报表） | 中 | 中（json/sarif/md） |

## 3) 关键观察（Key Insights）

1. 行业共识：`Detection` 已经是“标配能力”，核心竞争转向 `Remediation Automation`（自动撤销/替换/协作闭环）。
2. GitHub 强在“开发流入口”（push protection + bypass治理），但深度修复仍需外部工具协同。
3. GitGuardian 强在“事故处置系统化”（workflow + revocation + playbooks），是 SecretHawk 最直接的产品标杆。
4. TruffleHog 强在 `Verification`，把误报成本压低；这点可显著强化 SecretHawk 的信任度。
5. Gitleaks/detect-secrets 证明了 `baseline/allowlist` 的工程实用性，但在“自动修复”层普遍薄弱。

## 4) SecretHawk 强化空间（Opportunity Map）

```text
[当前优势: CLI + scan/patch/remediate骨架]
                 |
                 v
      [下一阶段差异化主轴]
      ├─ A. 验证可信度升级 (Verification Intelligence)
      ├─ B. 自动化修复闭环 (Rotate->Patch->CI Sync->Report)
      ├─ C. 团队治理能力 (Policy/SLA/Approval/Audit)
      └─ D. 低误报体验 (Context + Explain + Suggested Fix)
```

### A. Verification Intelligence

- 统一验证状态模型：`active / inactive / unknown / error`（已具备，需扩展 provider 覆盖）
- 增加 `confidence scoring`（规则命中 + 上下文 + 验证结果）
- 结果分层输出：默认只阻断 `verified active`，降低误报阻断

### B. 自动化修复闭环

- 连接器优先级：AWS -> GitHub -> Stripe -> Slack
- 一键链路：`revoke/rotate` -> `patch code` -> `update .env.example` -> `baseline update` -> `incident report`
- 补充 CI secret sync 能力（GitHub Actions Secrets / cloud secret manager）

### C. 团队治理能力

- 引入 delegated approval 思路（参考 GitHub bypass request）
- 策略加入 SLA、owner、escalation channel
- 事故状态机：`pending -> in_progress -> resolved -> accepted_risk`

### D. 开发者体验

- 自定义 remediation message（参考 ggshield）
- 每条 finding 输出“推荐动作序列”
- 代码补丁增加 language-aware import 修复（如 Python 自动补 `import os`）

## 5) 建议执行顺序（90天）

1. P0（0-30天）
   - AWS/GitHub 真正可用的验证与轮转
   - `scan --validate --fail-on active` 阻断策略
   - patch 语法安全增强 + 自动回归检查
2. P1（31-60天）
   - remediation playbook 模板化
   - CI secret sync（至少 GitHub Actions）
   - history-clean 自动化与回滚演练脚本
3. P2（61-90天）
   - 团队协作与审批流
   - SLA/审计输出
   - Connector marketplace 设计（插件化）

## 6) 数据来源（官方文档优先）

- GitHub: https://docs.github.com/code-security/tutorials/remediate-leaked-secrets/remediating-a-leaked-secret
- GitHub: https://docs.github.com/en/code-security/secret-scanning/introduction/about-push-protection
- GitHub: https://docs.github.com/en/code-security/secret-scanning/using-advanced-secret-scanning-and-push-protection-features/delegated-bypass-for-push-protection/about-delegated-bypass-for-push-protection
- GitHub Changelog: https://github.blog/changelog/2025-06-25-configuring-which-secret-scanning-patterns-are-included-in-push-protection-is-in-public-preview
- GitGuardian: https://docs.gitguardian.com/internal-monitoring/remediate/remediate-incidents
- GitGuardian CLI: https://docs.gitguardian.com/platform/gitguardian-suite/gitguardian-cli-ggshield
- TruffleHog: https://github.com/trufflesecurity/trufflehog
- TruffleHog docs: https://docs-next.trufflesecurity.com/docs/configuration/detector-specific-verification/
- Gitleaks: https://github.com/gitleaks/gitleaks
- detect-secrets: https://github.com/Yelp/detect-secrets
