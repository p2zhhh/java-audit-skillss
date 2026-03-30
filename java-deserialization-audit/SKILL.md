---
name: "java-deserialization-audit"
description: "Java 反序列化漏洞审查工具。深入扫描 ObjectInputStream、Fastjson、Jackson、XStream 等反序列化入口，检查 JEP 290 过滤及相关利用链（如 CC 链）风险。当用户要求审查反序列化漏洞或 JSON 解析安全时调用。"
---

# Java Deserialization Audit (Java 反序列化漏洞审查工具)

反序列化漏洞是 Java 安全中最为致命和复杂的漏洞类型之一。本工具结合了 Y4tacker 的 JavaSec 经验，专门用于扫描和分析 Java 项目中的反序列化入口，并评估其被利用的风险（如结合 CommonsCollections 等 Gadget 链）。

## 🎯 何时调用此 Skill (When to Invoke)

- 用户要求检查项目中的 “反序列化漏洞”、“JSON 注入” 或 “ObjectInputStream” 时。
- 审计包含 RMI、JMX、Dubbo 等 RPC 通信机制的代码时。
- 评估项目中引入的 Fastjson、Jackson、XStream 等组件的使用是否安全时。
- 作为 `java-ai-code-audit` 的重要深层扫描环节。

## 🔍 审查工作流 (Review Workflow)

1. **定位反序列化入口 (Identify Deserialization Sinks)**
   - **原生反序列化**: 搜索 `ObjectInputStream.readObject()`, `readUnshared()`, `XMLDecoder.readObject()`, `ObjectInputStream.resolveClass()`。
   - **JSON 库**:
     - Fastjson: `JSON.parseObject()`, `JSON.parse()`
     - Jackson: `ObjectMapper.readValue()`
   - **其他序列化库**:
     - XStream: `xstream.fromXML()`
     - Hessian: `HessianInput.readObject()`
     - SnakeYAML: `Yaml.load()`, `Yaml.loadAs()`

2. **数据流追踪与可控性分析 (Source to Sink Tracing)**
   **这是判断漏洞是否可利用的核心步骤。仅仅存在 Sink 点不等于存在漏洞，必须证明反序列化的数据是用户可控的。**
   - **Source 识别**: 检查传递给反序列化函数的数据流（如 `byte[]`, `InputStream`, `String json`）是否来源于 HTTP 请求（`@RequestBody`, `HttpServletRequest.getInputStream()`）、消息队列（如 Kafka 消费消息）、或未经校验的 RPC 调用入参。
   - **可控性评估**: 
     - **完全可控**: 数据流直接从网络接口流入 Sink。
     - **部分可控**: 数据流经过了签名校验、解密，或仅某几个字段被反序列化（需要结合密钥是否泄露或逻辑缺陷进一步分析）。
     - **不可控**: 数据流是从本地可信数据库、配置文件或内存缓存中读取的。

3. **验证安全配置与防御机制 (Verify Mitigations)**
   - **JEP 290**: 检查是否在 `ObjectInputStream` 上设置了 `ObjectInputFilter`（如 `setObjectInputFilter`）来进行白名单/黑名单过滤。
   - **Fastjson**: 检查是否开启了 `SafeMode` (`ParserConfig.getGlobalInstance().setSafeMode(true)`) 或 AutoType 配置是否严格。
   - **Jackson**: 检查是否全局开启了 `enableDefaultTyping()` 或使用了 `@JsonTypeInfo`，这通常是高危操作。如果必须使用，是否结合了安全的 `PolymorphicTypeValidator`。
   - **SnakeYAML**: 检查是否使用了安全的构造器 `new Yaml(new SafeConstructor())` 而不是默认构造器。

4. **依赖库环境分析 (Gadget Chain Context)**
   - 如果发现存在不受限的反序列化入口，需检查项目的 `pom.xml` 或 `build.gradle`，判断环境中是否存在经典的利用链（Gadgets）：
     - `commons-collections` (<= 3.2.1 或 4.0)
     - `commons-beanutils`
     - `rome`
     - `spring-aop`, `spring-beans`
     - `javassist`

## 📝 审计报告规范 (Audit Report Format)

**强制执行**: 当发现反序列化风险时，必须严格遵守全局审计报告输出规范：`../shared/references/audit_reporting_standards.md`。

在报告中，必须特别说明两点：1. **数据可控性**（数据是如何从外部流入 Sink 的）；2. **利用链情况**（未配置 JEP 290 Filter 且存在 Gadget 依赖）。

## 💡 AI 审查提示
- **联动追踪**: 当发现可疑的反序列化 Sink 时，务必结合或调用 `java-route-tracer` 技能，严格遵循 `../shared/references/taint_analysis_rules.md` 进行上下游的数据流分析，以排除那些反序列化本地可信文件或可信数据库内容的误报。

## 📚 参考资料说明
关于各反序列化库的危险特征、Gadget 链以及防御方案，请参阅 `references/deserialization_patterns.md`。
**全局共享规范**: 数据流追踪与报告格式必须遵守 `../shared/references/` 下的规则文档。