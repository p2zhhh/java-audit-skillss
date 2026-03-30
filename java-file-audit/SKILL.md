---
name: "java-file-audit"
description: "Java 文件操作与上传/下载漏洞审查工具。排查路径遍历、任意文件上传及危险扩展名处理。当要求检查文件上传、下载功能或目录穿越漏洞时调用。"
---

# Java File Audit (Java 文件安全审计工具)

文件操作（上传、下载、读取、写入）是 Web 应用程序最常见的功能之一，同时也是高危漏洞的频发区。本工具通过静态分析，自动化审计 Java 项目中的文件操作接口，旨在发现路径穿越（Path Traversal）、任意文件读取/下载以及不受限制的文件上传漏洞。

## 🎯 何时调用此 Skill (When to Invoke)

- 用户要求检查项目中的 “任意文件读取”、“路径穿越” 或 “文件上传漏洞” 时。
- 审计包含头像上传、附件下载、日志读取等功能的代码时。
- 作为 `java-ai-code-audit` 的重要安全检查环节。

## 📁 审查工作流 (Review Workflow)

1. **定位文件操作入口 (Identify File Operations)**
   - **文件上传 (Upload)**: 
     - 寻找 `@PostMapping` 或 Servlet 接口中处理 `MultipartFile` (Spring), `Part` (Servlet 3.0), 或 `FileItem` (Commons FileUpload) 的方法。
   - **文件读取/下载 (Read/Download)**: 
     - 寻找返回文件流、向 `HttpServletResponse.getOutputStream()` 写入数据的方法。
     - 寻找对 `java.io.File`, `java.nio.file.Paths`, `FileInputStream`, `Files.readAllBytes()` 等 API 的调用。

2. **数据流追踪与路径穿越检查 (Source to Sink Tracing)**
   对于文件读取和上传保存路径的拼接逻辑进行重点分析，**必须确认路径的组成部分受用户控制**：
   - **Source**: 检查文件名或相对路径参数是否来自外部（如 `@RequestParam("fileName")`、`MultipartFile.getOriginalFilename()`）。如果是写死的路径（如 `new File("/tmp/app.log")`），则不构成漏洞。
   - **Sanitizer**: 
     - 是否进行了路径规范化（如 `File.getCanonicalPath()`）并验证了基础目录（Base Directory）？
     - 是否过滤了 `../`, `..\\`, `%2e%2e%2f` 等穿越序列？
   - **Sink**: 判断拼接后的路径是否直接传入 `new File(path)` 或 `Paths.get(path)`。

3. **文件上传漏洞检查 (Arbitrary File Upload Check)**
   对于文件上传接口，必须检查以下安全措施的完整性：
   - **后缀名/MIME 检查**: 是否有严格的**白名单**后缀验证（如仅允许 `.jpg`, `.png`）？如果使用黑名单（如拦截 `.jsp`），检查是否可被绕过（如 `.jspx`, `.Jsp`, `.jsp%00`）。
   - **内容校验**: 是否检查了文件头（Magic Number）或进行了图像重渲染？
   - **存储位置**: 上传的文件是否存储在 Web 目录之外？如果存储在 Web 目录下，是否禁用了脚本执行权限？
   - **文件名随机化**: 保存时是否对文件名进行了随机化重命名（如 `UUID.randomUUID()`），而不是直接使用用户传入的 `MultipartFile.getOriginalFilename()`。

## 📝 审计报告规范 (Audit Report Format)

**强制执行**: 当发现文件操作风险时，必须严格遵守全局审计报告输出规范：`../shared/references/audit_reporting_standards.md`。

在报告中，必须详细说明**用户输入是如何影响文件路径或内容的**。

## 💡 AI 分析提示

- **关注 `getOriginalFilename()`**: 很多开发者认为 `MultipartFile.getOriginalFilename()` 是安全的，实际上该值由客户端控制，可能包含 `../` 导致跨目录上传（例如上传到 `/etc/cron.d/` 或 `WEB-INF/` 目录下）。
- **Null Byte Injection (`%00`)**: 检查旧版 Java 中是否存在截断漏洞（尤其是 JDK 1.7.0_40 之前）。
- **结合全局防误报**: 在判定路径穿越时，严格遵循 `../shared/references/taint_analysis_rules.md` 判断路径是否可控，并检查是否存在全局的 FileFilter。

## 📚 参考资料说明
关于文件上传和路径穿越的详细防御规范，请参阅 `references/file_security.md`。
详细的文件操作高危 Sink 与安全过滤特征匹配规则，请参考 `references/file_vuln_patterns.md`。
**全局共享规范**: 数据流追踪与报告格式必须遵守 `../shared/references/` 下的规则文档。