# 数据流分析：Source 与 Sink 识别规则

在进行污点追踪（Taint Analysis）时，准确识别污染源（Source）和危险接收端（Sink）是核心步骤。

## 1. 污染源 (Source)
这些是外部用户可控的数据输入点。

### 1.1 Spring 框架 Source
- `@RequestParam` / `@PathVariable` / `@RequestBody` / `@RequestHeader`
- `HttpServletRequest` 的方法:
  - `getParameter(String)`
  - `getHeader(String)`
  - `getCookies()`
  - `getInputStream()` / `getReader()`
- 隐式 Source:
  - 从 ThreadLocal 或 SecurityContext 中取出的、由前端请求填充的数据。

### 1.2 其他常见 Source
- 数据库查询结果（在进行二次注入分析时作为 Source）。
- 从外部文件、网络接口读取的数据。

## 2. 危险目标 (Sink)
参数如果未经安全过滤流入这些点，将构成漏洞。

### 2.1 数据库操作 (SQL 注入 Sink)
- JDBC `Statement.execute/executeQuery/executeUpdate`
- MyBatis Mapper 的 `${}` 参数绑定。
- Hibernate/JPA 动态拼接的 `createQuery`。

### 2.2 文件操作 (路径穿越/任意文件读写 Sink)
- `new java.io.File(path)`
- `java.nio.file.Paths.get(path)`
- `new java.io.FileInputStream(path)` / `FileOutputStream(path)`

### 2.3 命令执行 (Command Injection Sink)
- `java.lang.Runtime.getRuntime().exec(...)`
- `new java.lang.ProcessBuilder(...)`

### 2.4 网络请求 (SSRF Sink)
- `new java.net.URL(url).openConnection()`
- HttpClient `execute()`
- OkHttp `newCall()`

### 2.5 响应输出 (XSS Sink)
- `HttpServletResponse.getWriter().write/print(...)`
- Thymeleaf/Freemarker 模板中未转义的变量渲染。

## 3. 跨层级追踪实战技巧 (Cross-Layer Tracing)

为了保证追踪准确率，在遇到多层链路时，需采用以下策略：

1. **解决接口断层问题**:
   - 在 Spring 框架中，Controller 通常注入的是 `IUserService` 接口。当看到 `userService.doSomething(userInput)` 时，必须使用全局搜索或类名匹配，找到实现了 `IUserService` 的 `UserServiceImpl` 类。
   - 追踪必须进入 `UserServiceImpl.doSomething` 方法的内部。

2. **解决对象封装问题 (DTO/Entity)**:
   - 很多时候数据不是以基本类型（如 `String`）传递，而是被 Spring MVC 封装成了 DTO 对象：`public void update(UserDTO user)`。
   - 此时在 Service 层，必须盯着 `user.getUsername()` 或 `user.getFilePath()` 等 Getter 方法的调用，确认取出的受控属性是否进入了 Sink。

3. **消解同名函数与弱类型的搜索歧义 (Disambiguation)**:
   - 当在深层工具类（如 `com.common.FileUtils.read(String path)`）中发现 Sink 时，如果只搜索 `"read("` 会产生海量无用结果。
   - **应对类名与变量名完全相同的情况**:
     如果在不同的模块中都有一个叫 `FileUtils` 的类，且都有 `read` 方法，甚至注入的变量名都叫 `fileUtils`。此时**绝对不能**仅仅看到 `fileUtils.read()` 就认为链路接通。
     - **必须向上查找变量声明**: 在当前类中搜索 `fileUtils` 的声明（如 `private FileUtils fileUtils;` 或参数列表中的 `FileUtils fileUtils`）。
     - **核对全限定名**: 找到声明后，查看当前文件顶部的 `import` 列表。如果 `import` 的是 `com.other.FileUtils` 而不是你正在追踪的 `com.common.FileUtils`，则**此调用链不成立，必须果断判定为误报分支**。
     - **⚠️ 强制穷举覆盖 (Exhaustive Coverage)**: 放弃当前错误分支后，**绝不能停止追踪**！必须回到 `SearchCodebase` 或 `Grep` 的搜索结果列表中，继续排查下一个疑似调用点，直到**覆盖所有找到的疑似链路方法**，或者成功找到一条完整的可控链路为止。