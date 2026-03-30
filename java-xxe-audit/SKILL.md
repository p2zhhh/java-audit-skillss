---
name: "java-xxe-audit"
description: "Java XXE (XML 外部实体注入) 漏洞审计工具。自动识别 XML 解析操作，检查是否正确禁用了 DTD 和外部实体。当要求排查 XXE 漏洞或审查 XML 处理逻辑时调用。"
---

# Java XXE Audit (Java XXE 漏洞审查工具)

XML External Entity (XXE) 注入是由于 XML 解析器未正确配置，导致攻击者能够通过恶意的 XML 数据读取本地文件、执行 SSRF 或造成拒绝服务攻击。此工具专门用于扫描 Java 项目中的 XML 处理逻辑，验证解析器的安全配置。

## 🎯 何时调用此 Skill (When to Invoke)

- 用户要求检查项目中的 “XXE漏洞” 或 “XML 安全问题” 时。
- 审计包含 Excel 导入 (POI)、PDF 解析、SAML 断言处理、SVG 渲染或 SOAP Web Services 的代码时。
- 作为 `java-ai-code-audit` 的特定类型漏洞扫描模块。

## 🔍 审查工作流 (Review Workflow)

1. **定位 XML 解析点 (Identify Parsers)**
   使用 `Grep` 或 `SearchCodebase` 寻找常见的 Java XML 解析 API 的实例化操作：
   - `DocumentBuilderFactory.newInstance()`
   - `SAXParserFactory.newInstance()`
   - `XMLReaderFactory.createXMLReader()`
   - `XMLInputFactory.newInstance()`
   - 第三方库：`SAXReader` (dom4j), `SAXBuilder` (JDOM), `Digester` (Commons Digester)

2. **验证安全配置 (Verify Security Configurations)**
   对于找到的每个解析器实例，必须检查紧随其后的配置代码，确认是否显式禁用了外部实体。
   
   **✅ 安全的配置特征 (Safe Patterns):**
   - 设置 `FEATURE_SECURE_PROCESSING` 为 `true`。
   - 禁用 DTD：`setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`
   - 禁用外部通用实体：`setFeature("http://xml.org/sax/features/external-general-entities", false)`
   - 禁用外部参数实体：`setFeature("http://xml.org/sax/features/external-parameter-entities", false)`

   **❌ 危险的特征 (Vulnerable Patterns):**
   - 实例化了解析器，但**没有任何** `setFeature` 或 `setProperty` 的安全配置。
   - 虽然进行了配置，但通过流程控制（如 `if` 语句）可能被绕过。

3. **数据流追踪与可控性分析 (Source to Sink Tracing)**
   如果发现了解析器配置不当（Sink），必须反向追踪（结合 `java-route-tracer` 的思想），确认传入的 XML 字符串、`InputStream` 或 `File` 是否来自于不受信任的用户输入（Source）。
   - **完全可控**: 从 `@RequestBody`, `MultipartFile` 或直接从 HTTP 请求中读取 XML 流。
   - **不可控**: 解析的 XML 是项目中打包的配置文件（如 `classpath:config.xml`）或来自可信的内部服务，此时即使解析器未配置防御，也不构成 XXE 漏洞。

## 📝 审计报告规范 (Audit Report Format)

**强制执行**: 当发现 XXE 风险时，必须严格遵守全局审计报告输出规范：`../shared/references/audit_reporting_standards.md`。

在报告中，必须**明确证明 XML 数据流是用户可控的**，并在修复建议中提供具体的安全配置代码块。

## 💡 AI 审查重点

- **框架默认行为**: 不同的 Java 版本和不同的第三方库对 XXE 的默认防护行为不同。若代码中未显式配置，应默认将其标记为“潜在风险 (Potential Risk)”，并建议补充显式防御代码以提高纵深防御能力。
- **Spring 框架**: 如果使用了 Spring 的 `@RequestBody` 接收 XML（如结合 Jackson-dataformat-xml），通常需要检查 Jackson 的配置是否安全。
- **强制防误报**: 如果发现 XML 解析的是本地配置文件（不满足全局 `taint_analysis_rules.md` 中的可控性要求），禁止报告为漏洞。

## 📚 参考资料说明
关于各种 XML 解析器的安全配置代码，请参阅 `references/xxe_prevention.md`。
常见解析器的实例化及安全/危险特征匹配规则，请参考 `references/xxe_patterns.md`。
**全局共享规范**: 数据流追踪与报告格式必须遵守 `../shared/references/` 下的规则文档。