---
name: "java-ai-code-audit-pipeline"
description: "Trae 专属 Java 代码安全审计全自动流水线。当你需要一键自动执行完整的代码审计（反编译、路由提取、鉴权扫描、组件扫描、漏洞深挖、最终汇总）时调用此技能。它会自动使用 Agent Team 进行多阶段的并发调度和质检。"
---

# 🚀 Trae Java Security Audit Automated Pipeline

这是一个专为 Trae 设计的**全自动化 Java 安全审计编排技能**。它通过实例化多个专门的 Agent（即本项目的各个子 Skill），按照严格的 5 阶段流水线进行多线程协同工作，最终生成一份高质量、无误报的安全审计报告。

## 🎯 触发条件
当用户要求：“帮我用流水线审计一下这个项目”、“一键审计这几个 jar 包”、“全量执行代码扫描”、“反编译并扫描这些 class 文件”时，调用此 Skill。

## 🛠️ 工作流引擎编排规则 (Workflow Orchestration)

作为主控节点，你必须严格按照以下顺序和依赖关系，**主动分配任务并调用相应的子 Skill**，而不是让用户一步步指导。

### 📌 前置准备 (Preparation)
1. **输入解析**: 获取用户提供的源码路径或 `.jar`/`.class` 文件路径（如 `WEB-INF/classes` 目录）。
2. **反编译 (如果需要)**: 如果目标是 `.jar` 文件或包含大量 `.class` 文件的目录，必须先调用 `.trae/skills/shared/scripts/batch_decompile_mapper.py` 或 `auto_decompile.py` 将其还原为 Java 源码结构。所有后续分析必须基于还原后的源码目录。

### 📌 阶段 1: 基础设施与靶标收集 (Reconnaissance)
*此阶段可以并行执行。*
- **任务 A (路由提取)**: 调用 `java-route-mapper` 技能，运行 AST 脚本提取全站路由及参数，生成 `routes.json`。
- **任务 B (鉴权映射)**: 调用 `java-auth-audit` 技能，识别项目的鉴权机制（如 Spring Security/Shiro），生成路由的鉴权状态报告。
- **任务 C (组件扫描)**: 调用 `java-vuln-scanner` 技能，扫描 `pom.xml`，识别高危依赖。

### 📌 阶段 2: 漏洞专精并发扫描 (Deep Scanning)
*等待阶段 1 完成后启动。将阶段 1 收集到的靶标（未授权路由、参数）分配给以下专精 Agent。*
- **SQL 审计**: 调用 `java-sql-audit` 检查 MyBatis/Hibernate 等。
- **业务逻辑审计**: 调用 `java-business-logic-audit` 结合鉴权状态排查越权和逻辑漏洞。
- **其他专项审计**: 根据阶段 1 的组件扫描结果按需触发（如 `java-shiro-audit`, `java-spring-cloud-audit`, `java-xxe-audit`, `java-deserialization-audit`）。

### 📌 阶段 3: 链路确诊与防误报 (Validation)
*每个专精 Agent 发现疑似漏洞（Sink）后触发。*
- **调用链追踪**: 调用 `java-route-tracer` 技能，从发现的 Sink 逆向追踪到 Controller。
- **可控性判定**: 严格依据 `shared/references/taint_analysis_rules.md` 判断 Source 参数是否为外部用户可控输入，排除内部注入对象（如 `HttpServletRequest`）导致的误报。

### 📌 阶段 4: 最终报告汇总 (Reporting)
*等待所有阶段完成。*
- 汇总所有确诊（链路完整且可控）的漏洞。
- 严格按照 `shared/references/audit_reporting_standards.md` 的格式，输出最终的 Markdown 报告（必须包含漏洞类型、精确的代码文件及行号、鉴权要求、完整的利用调用链以及可利用的 POC 模板）。
- 必须包含安全建议及修复方案。
- **【强制】报告聚合与规范化要求**：
  - 必须通过全局搜索并读取各个子阶段的产出物（如 `auth_audit/`、`sql_audit/`、`vuln_report/` 等），将其核心高危漏洞 100% 整合进总报告，不得遗漏。
  - 每个记录的高危/严重漏洞**必须**提供以下详细结构：
    - **漏洞位置**: 包含具体的类名、文件路径和精确代码行号。
    - **是否需要鉴权**: 明确标出触发该漏洞是否需要鉴权（例如：不需要、需要 Token、特定角色等）。
    - **调用链 (Call Chain)**: 清晰列出从入口（如 Controller/Filter）到危险汇聚点（Sink/下游转发）的完整代码执行路径。
    - **利用详情与 PoC**: 阐述漏洞触发原理，并提供可以直接用于复现或验证的 HTTP 请求模板（PoC）或攻击 Payload。

## ⚠️ 运行时约束
1. **自动执行**: 这是一个自动化流水线，在各个阶段切换时，**不需要询问用户是否继续**，你应该自动完成整个流程直到最后生成报告。
2. **状态汇报**: 在执行耗时较长的脚本（如批量反编译、AST 提取）时，请向用户简要汇报当前进度。
3. **隔离性**: 本流水线完全依赖于本代码库 `.trae/skills/` 下的工具，**绝对禁止调用全局或系统其他位置同名的 `java-audit-pipeline` 技能**。
