---
name: "java-route-tracer"
description: "Java 数据流分析与调用链追踪工具。用于追踪从外部输入（Source）到危险操作（Sink）的完整代码链路。当需要验证参数传递或排查跨层调用的漏洞时调用。"
---

# Java Route Tracer (Java 调用链分析器)

在安全代码审计中，单独分析某个危险函数（Sink）是不够的，我们需要确认外部不可信的输入（Source）是否能够到达该函数。此工具旨在通过静态分析，自动化追踪 Java 应用程序中数据的流向，揭示 Controller -> Service -> DAO（或底层系统调用）的完整调用链路。

## 🎯 触发条件 (When to Invoke)

- 用户要求：“追踪这个参数”、“看看这个漏洞能不能触发”、“分析一下从 Controller 到 DAO 的调用链” 时。
- 配合漏洞审计工具（如 `java-sql-audit`, `java-ai-code-audit`），用于确诊（Confirm）潜在的注入点是否受外部控制。

## 🔎 数据流追踪流程 (Tracing Workflow)

1. **入口点分析 (Source Identification)**
   - **定位路由**: 寻找带有 `@RequestMapping`, `@GetMapping`, `@PostMapping` 的方法。
   - **提取参数**: 识别外部控制的数据来源，如 `@RequestParam`, `@PathVariable`, `@RequestBody`，或原生的 `HttpServletRequest.getParameter()`。

2. **跨层调用追踪 (Cross-Layer Call Tracing)**
   - **Service 层**: 追踪 Controller 中如何将参数传递给 Service 层的对应方法。注意接口（Interface）与实现类（Impl）的映射关系。
   - **方法签名匹配**: 重点追踪参数的类型转换、对象封装（如装箱入 DTO）。
   - **依赖注入**: 分析通过 `@Autowired`, `@Resource`, `@Inject` 注入的 Bean 实例，跟踪其方法的具体实现。

3. **危险目标定位 (Sink Identification)**
   - **数据库操作**: DAO 层的 `insert`, `update`, `query`，或 MyBatis Mapper、Hibernate 的 HQL 执行。
   - **文件系统**: `java.io.File`, `Files.write()`, `FileInputStream` 等。
   - **命令执行**: `Runtime.getRuntime().exec()`, `ProcessBuilder`。
   - **序列化与反射**: `ObjectInputStream`, `Class.forName()`, `Method.invoke()`。
   - **外部请求 (SSRF)**: `HttpURLConnection`, `RestTemplate`, `HttpClient`。

4. **净化机制检查 (Sanitization Check)**
   - 在 Source 到 Sink 的调用链上，必须特别注意是否存在过滤、编码或转义逻辑。
   - 例如：URL 编码解码、HTML 实体转义、正则替换、类型强转（如 `String` 转 `Integer`）。
   - **AI 推理**: 评估这些净化机制的严谨性，判断是否存在绕过（Bypass）的可能性。

## 📝 追踪报告格式 (Tracer Report Format)

**强制执行**: 在输出追踪结果时，必须严格遵守共享目录中的全局审计报告输出规范：`../shared/references/audit_reporting_standards.md`。

除此之外，调用链报告还必须清晰地展示**数据流向 (Data Flow)**，例如：
1. `Controller.doAction(String param)` -> [Controller.java:50](file:///path/to/controller#L50)
2. `Service.process(String param)` -> [ServiceImpl.java:80](file:///path/to/service#L80)
3. `DAO.execute(String param)` -> [DAOImpl.java:120](file:///path/to/dao#L120)

## 💡 AI 分析重点

- **多态与重载**: 在追踪时，遇到接口的方法调用，必须搜索其所有实现类（Impl），判断运行时究竟执行的是哪段代码。
- **隐式传递**: 注意通过 `ThreadLocal`、`RequestContextHolder` 等隐式方式传递的上下文数据。
- **强制可控性验证**: 必须遵守全局 `taint_analysis_rules.md` 规则，准确评估参数是否真的受用户控制。
- **利用 AST 工具防幻觉**: 遇到动辄几千行的 `ServiceImpl` 文件时，**禁止使用 Read 工具强行读取整个文件**（这会导致 Token 爆炸和严重幻觉）。请使用 `python ../shared/scripts/ast_extractor.py <文件路径> <目标方法名>`，它会精准提取 `import` 列表、成员变量声明和你需要追踪的那个方法的完整代码块。

## 📚 参考资料说明
关于数据流追踪和污点分析的相关理论，请参阅 `references/taint_analysis.md`。
具体的 Source (污染源) 与 Sink (危险目标) 匹配规则，请参考 `references/source_sink_patterns.md`。
**全局共享规范**: 数据流追踪与报告格式必须遵守 `../shared/references/` 下的规则文档。