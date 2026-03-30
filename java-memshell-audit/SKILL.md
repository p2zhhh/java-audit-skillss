---
name: "java-memshell-audit"
description: "Java 内存马注入与类加载后门审查工具。检测针对 Servlet/Filter/Listener 动态注册、Tomcat Valve、JavaAgent 及自定义 ClassLoader 的恶意代码模式。当要求排查内存马、后门或代码执行漏洞时调用。"
---

# Java Memshell Audit (Java 内存马审查工具)

内存马（Memory Web Shell）是 Java Web 攻防中的高级对抗技术。攻击者通过利用反序列化、JNDI 注入等 RCE 漏洞，动态地向运行中的 Web 容器（如 Tomcat, Spring）注入恶意的 Filter、Servlet 或 Valve，从而实现无文件落地（Fileless）的持久化后门。

本工具用于在源码层面排查可能导致内存马注入的动态注册逻辑，以及在应急响应/代码审计中寻找潜在的恶意后门特征。

## 🎯 何时调用此 Skill (When to Invoke)

- 用户明确要求检查 “内存马”、“无文件后门” 或 “JavaAgent” 时。
- 审计包含大量动态类加载（ClassLoader）或反射调用的代码时。
- 检查应用中是否存在异常的 Filter、Servlet、Listener 动态注册逻辑时。
- 作为高级 `java-ai-code-audit` 的补充模块。

## 🕵️‍♂️ 审查工作流 (Review Workflow)

1. **数据流与 Payload 可控性分析 (Source to Sink)**
   **这是区分正常业务动态注册与内存马注入的核心标准。**
   - 如果 `addFilter` 或 `defineClass` 的字节码/类名是项目内部写死的常量，这是正常的框架行为。
   - **高危特征**: 注入的类名、字节码（`byte[]`）或恶意脚本来源于 HTTP 请求（如 `request.getParameter()`, `request.getReader()`）或从不可信的远端服务器下载。

2. **容器级动态注册排查 (Dynamic Registration in Containers)**
   - **Servlet API**: 搜索 `ServletContext` 的 `addFilter()`, `addServlet()`, `addListener()` 方法调用。结合上述可控性分析，检查被注册的类是否来源于不受信任的输入或动态生成的字节码。
   - **Tomcat 特有**: 搜索 `StandardContext`, `ApplicationFilterConfig`, `Pipeline`, `Valve` 等 Tomcat 内部 API 的反射调用。
   - **Spring 特有**: 搜索针对 `RequestMappingHandlerMapping` 或 `Controller` 的动态注册代码。

3. **字节码与类加载操作 (Bytecode & ClassLoading)**
   - **自定义 ClassLoader**: 搜索继承了 `ClassLoader` 并重写 `defineClass()` 的代码。重点关注从网络流 (`byte[]`) 或 Base64 解码后直接加载类的逻辑。
   - **字节码操作库**: 寻找 `javassist.ClassPool`, `org.objectweb.asm.ClassWriter`, `org.springframework.cglib.core.ReflectUtils.defineClass()` 的可疑调用。
   - **JavaAgent**: 检查项目中是否包含可疑的 `premain` 或 `agentmain` 方法，以及使用了 `java.lang.instrument.Instrumentation` 的代码。

4. **恶意 Payload 特征匹配 (Payload Signatures)**
   - **反射执行命令**: 搜索复杂的反射调用链，如通过 `Class.forName("java.lang.Runtime")` 获取实例并调用 `exec`，这种写法通常为了绕过简单的静态扫描。
   - **隐蔽参数获取**: 检查 Filter/Servlet 的 `doFilter` 或 `service` 方法中，是否包含类似 `request.getParameter("cmd")` 且紧跟命令执行或脚本求值的逻辑。
   - **流量混淆**: 注意 `Cipher`, `Base64.getDecoder()`, 或异或操作等解密 payload 的逻辑。

## 📝 审计报告规范 (Audit Report Format)

**强制执行**: 当发现可疑的内存马特征或动态注入逻辑时，必须严格遵守全局审计报告输出规范：`../shared/references/audit_reporting_standards.md`。

在报告的“逻辑分析”部分，必须详细描述可疑代码的行为，并证明其符合全局 `taint_analysis_rules.md` 中的高危特征。例如：“该方法通过反射获取了 `StandardContext`，并动态调用 `addFilterDef` 注册了一个名为 `evil` 的 Filter，且 Filter 的字节码来源于外部传入的 Base64 字符串（完全受控），这是典型的 Tomcat 内存马注入特征。”

## 📚 参考资料说明
关于各类型内存马（Filter/Servlet/Valve/JavaAgent）的注入原理及代码特征，请参阅 `references/memshell_patterns.md`。
**全局共享规范**: 数据流追踪与报告格式必须遵守 `../shared/references/` 下的规则文档。