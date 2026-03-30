---
name: "java-vuln-scanner"
description: "Java 第三方组件漏洞扫描工具。解析 pom.xml 或 build.gradle，识别并报告项目中引入的已知高危版本依赖（如 Fastjson, Log4j2）。"
---

# Java Vulnerability Scanner (Java 组件漏洞扫描器)

现代 Java 应用高度依赖第三方开源组件（SCA - Software Composition Analysis）。如果项目中引入了包含已知 CVE 漏洞的组件（如著名的 Log4j2 JNDI 注入、Fastjson 反序列化），应用将面临极大的安全风险。本工具通过解析项目依赖配置文件，快速排查潜在的组件漏洞。

## 🎯 何时调用此 Skill (When to Invoke)

- 用户要求“检查第三方依赖漏洞”、“扫描项目组件安全”时。
- 审计一个新接手的 Java 项目前，作为快速排查安全基线的步骤。
- 在 `java-ai-code-audit` 流程中执行“第三方组件检查”阶段。

## 📦 扫描工作流 (Scanning Workflow)

**强制工具调用**: 在进行组件扫描时，**严禁使用普通的文本搜索或阅读工具去生啃 `pom.xml` 文件**。由于 POM 文件中存在复杂的 `<properties>` 变量替换和标签嵌套，大模型极易产生读取遗漏或幻觉。

1. **执行自动化解析脚本**:
   请直接打开终端执行以下命令：
   ```bash
   python .trae/skills/java-vuln-scanner/scripts/pom_parser.py <项目根目录>
   ```
2. **分析脚本输出结果**:
   该脚本会利用标准的 XML 解析器提取所有的依赖，自动处理 `${version}` 变量替换，并与内置的高危指纹库进行正则匹配。
   你需要将脚本的输出结果直接采纳，并整理成最终的报告。

3. **间接依赖分析提示 (Transitive Dependency Note)**
   - 静态解析 `pom.xml` 只能发现显式声明的直接依赖（Direct Dependencies）。
   - 需在报告中提示：可能存在未声明的间接依赖（Transitive Dependencies）漏洞，建议用户使用 `mvn dependency:tree` 或专用 SCA 工具进行深度扫描。

## 📊 扫描报告规范 (Scanner Report Format)

**强制执行**: 在输出组件漏洞扫描结果时，必须严格遵守全局审计报告输出规范：`../shared/references/audit_reporting_standards.md`。

报告中必须明确说明**已知漏洞的具体影响**和**安全的升级版本号**。

## 💡 AI 分析策略

- **版本号推理**: 有些版本号可能定义在父 POM（`<parent>`）或 `<properties>` 标签中。如果遇到 `${fastjson.version}`，必须通过全文搜索或文件读取，找到该变量的真实定义值后再进行评估。
- **环境上下文**: 某些组件漏洞的利用依赖特定的 JDK 版本（如 JNDI 注入在较新 JDK 中默认受到一定限制），在报告时可附带相关环境前提条件的说明。
- **结合全局分析**: 遵循 `../shared/references/audit_reporting_standards.md`，检查低版本组件的危险功能是否在业务代码中被实际调用，如果仅引入未调用，应降级处理。

## 📚 参考资料说明
关于第三方组件漏洞管理的资源，请参阅 `references/vuln_management.md`。
**全局共享规范**: 数据流追踪与报告格式必须遵守 `../shared/references/` 下的规则文档。