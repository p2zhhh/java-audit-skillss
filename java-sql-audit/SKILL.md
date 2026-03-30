---
name: "java-sql-audit"
description: "深度识别 Java 数据库交互逻辑，检测潜在 SQL 注入的审计工具。重点排查拼接、动态查询及非参数化风险。当要求排查数据库安全或 SQL 注入漏洞时调用。"
---

# Java SQL Audit (Java SQL 注入审查工具)

此工具专门用于分析 Java 应用程序的数据库交互层（DAO/Mapper 层），检测潜在的 SQL 注入（SQLi）漏洞。通过模式识别与参数化检查，定位所有未经过滤即执行的动态 SQL 查询。

## 🎯 何时调用此 Skill (When to Invoke)

- 用户要求检查项目中的 “SQL注入漏洞” 时。
- 审计使用 MyBatis、Hibernate 或纯 JDBC 的持久层代码时。
- 作为 `java-ai-code-audit` 或安全流水线的一部分被调度执行。

## 🕵️‍♂️ 审查工作流 (Review Workflow)

1. **框架定位与自动化提取 (Framework Detection & Automated Extraction)**
   - 确定项目中使用的 ORM 或数据库访问技术栈。
   - **首选自动化工具 (MyBatis)**: 如果发现项目使用了 MyBatis（存在 `*Mapper.xml`），**必须优先调用专属提取脚本**来提取包含 `${}` 的 SQL 片段，避免 AI 直接读取大段 XML 产生遗漏或解析错误：
     ```bash
     python .trae/skills/java-sql-audit/scripts/mybatis_sql_extractor.py -d <project_dir> -o mybatis_sqli_risks.json
     ```
     根据生成的 JSON 文件快速定位风险点。
   - **其他框架/无 XML 的 MyBatis**:
     - **Hibernate/JPA**: 查找 `@Query` 注解、`EntityManager` 的 `createQuery()`、`createNativeQuery()` 方法。
     - **JDBC**: 搜索 `java.sql.Connection`、`Statement`、`PreparedStatement`、`ResultSet`。

2. **漏洞模式匹配 (Vulnerability Pattern Matching)**
   针对不同框架，检查以下高危模式（Sink）：
   - **MyBatis (`$` 拼接)**:
     - 在 XML Mapper 或注解中寻找 `${}` 语法。重点审查 `ORDER BY ${column}`, `LIKE '%${value}%'`, 以及 `IN (${ids})` 这类常见的拼接场景。
     - **说明**: MyBatis 的 `#` 是安全的参数化预编译，而 `$` 是直接字符串拼接，极易导致注入。
   - **Hibernate / JPA (动态 HQL / Native SQL)**:
     - 检查 HQL 字符串拼接（例如：`"FROM User WHERE username = '" + name + "'"`）。
     - 关注非参数化查询调用，如未通过 `.setParameter()` 绑定参数，而是直接传入带变量的字符串。
   - **JDBC (字符串拼接)**:
     - 检查是否使用了 `Statement.executeQuery()` 和 `Statement.executeUpdate()`，且传入的 SQL 语句是由 `+` 拼接而成。
     - 检查 `PreparedStatement` 中是否也混杂了动态拼接的表名或字段名。

3. **数据流追踪与可控性分析 (Source to Sink Tracing)**
   **这是确认漏洞是否可利用的关键步骤。**
   - 发现上述拼接模式（Sink）后，必须向调用链的上游（DAO -> Service -> Controller）反向追溯。
   - **确认来源 (Source)**: 证明传入 SQL 拼接点的数据确实来自于不受信任的用户输入（如 `@RequestParam`），而非系统内部写死的常量或白名单枚举值。

4. **过滤与绕过分析 (Filter & Bypass Analysis)**
   - 检查参数在流入 Sink 之前，是否经过了严格的白名单校验（例如 `if (Arrays.asList("id", "name").contains(orderBy))`）。
   - 如果只有简单的黑名单替换（如 `replace("'", "")`），尝试分析其是否可以被绕过。

## 📝 审计报告规范 (Audit Report Format)

**强制执行**: 输出报告时，必须严格遵守全局审计报告输出规范：`../shared/references/audit_reporting_standards.md`。

在漏洞描述中，必须包含**数据流可控性说明**，例如：“`ORDER BY ${sortField}` 直接拼接了 Controller 层传来的 `sortField` 参数，且未做任何校验，属于完全可控的 ORDER BY 型注入。”

## 💡 AI 审查建议

- **强制防误报校验**: 有些 `$` 变量可能在代码内部被写死，或其来源完全受控（如从配置文件读取），这种情况下属于安全用法，请遵循全局 `taint_analysis_rules.md` 排除误报。
- **关注边界情况**: LIKE 查询、IN 查询、以及动态的表名/列名是 SQL 注入的重灾区，需作为审查的优先级最高项。

## 📚 参考资料说明
关于各 ORM 框架的安全查询构建方法，请参阅 `references/sqli_prevention.md`。
详细的 SQL 注入特征与高危代码模式，请参考 `references/sqli_patterns.md`。
**全局共享规范**: 数据流追踪与报告格式必须遵守 `../shared/references/` 下的规则文档。