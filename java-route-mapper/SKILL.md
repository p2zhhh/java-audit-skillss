---
name: "java-route-mapper"
description: "Java Web路由结构提取与API映射工具。自动分析控制器注解与配置，生成完整的API端点列表。当需要梳理项目所有接口、参数信息或生成测试请求模板时调用此技能。"
---

# Java Route Mapper (Java 路由提取器)

在进行安全审计、代码重构或无文档 API 测试时，了解应用的所有访问端点（Endpoints）是至关重要的第一步。本工具通过静态分析 Java 代码库，提取所有对外暴露的 HTTP 路由及其参数，生成结构化的接口清单。

## 🎯 触发场景 (When to Invoke)
- 用户要求：“列出所有接口”、“分析当前项目的路由”、“梳理所有的 Controller” 或 “生成 Burp 测试请求模板” 时。
- 作为其他安全审计工具（如 `java-sql-audit`, `java-ai-code-audit-pipeline`）的前置依赖步骤，帮助确定攻击面。

## 🛠️ 执行流程与分析规则 (Execution Workflow)

1. **框架特征识别 (Framework Detection)**
   - 快速扫描项目依赖 (`pom.xml` / `build.gradle`)，确定目标使用的是哪种 Web 框架。
   - **Spring MVC / Spring Boot**: 寻找带有 `@RestController`, `@Controller` 的类。
   - **JAX-RS (Jersey / RESTEasy)**: 寻找 `@Path` 注解的类和方法。
   - **Struts 2**: 寻找 `struts.xml` 配置文件或继承 `ActionSupport` 的类。
   - **Servlet**: 寻找 `web.xml` 中的 `<servlet-mapping>` 或带有 `@WebServlet` 注解的类。

2. **自动化端点提取 (Automated Extraction) - 首选**
   - 对于 Spring 框架项目，**必须优先使用基于 AST 的提取脚本**进行路由提取，它能精准解析数组绑定与接口继承：
     ```bash
     python .trae/skills/java-route-mapper/scripts/spring_route_extractor.py -d <project_dir> -o routes.json
     ```
   - **🚨 常量路由解析规则 (Constant Resolution)**：
     如果 `routes.json` 中的 `path` 包含 `CONST:` 前缀（如 `CONST:ApiConstants.USER_PATH`），说明路由使用了常量定义。**你必须主动使用 `Grep` 或 `SearchCodebase` 工具，全局搜索该常量（如 `ApiConstants` 类中的 `USER_PATH`）的真实字符串值**，将其替换还原为完整路径。
   - **🌐 Context Path 处理**：
     脚本会自动尝试从 `application.yml` / `properties` 提取 `context-path` 并拼接。如果发现提取结果异常或缺失前缀，请手动确认配置文件中的 `server.servlet.context-path` 设置。
   - 读取最终完善后的 `routes.json`，在此基础上进行进一步的参数分析。

3. **深度端点分析 (Deep Endpoint Analysis)**
   基于自动提取的路由列表（或针对非 Spring 框架手动检索的结果），提取出每一个端点的详细参数信息：
   - **HTTP 方法**: `GET`, `POST`, `PUT`, `DELETE` 等。
   - **完整 URL 路径**: 结合类级别的路径与方法级别的路径进行拼接。
   - **参数列表**: 
     - **Query/Form 参数**: 提取 `@RequestParam`。
     - **路径变量**: 提取 `@PathVariable`。
     - **请求体**: 提取 `@RequestBody` 并尽可能推断其数据模型（如对应的 DTO 或 Entity 结构，建议结合 `ast_extractor.py` 读取 DTO 结构）。

3. **结果文档化 (Documentation Generation)**
   - 必须以 Markdown 格式输出提取到的所有接口清单，不得遗漏。
   - 针对每个接口，生成一个可以直接用于安全测试（如 Burp Suite）的 HTTP 请求报文模板。

## 📝 输出模板要求 (Output Format)

输出必须包含清晰的 API 列表，格式参考如下：

### API 列表汇总
| 请求方法 | 路由路径 | 对应方法签名 | 参数及来源 |
| :--- | :--- | :--- | :--- |
| `POST` | `/api/login` | `UserController.login` | `@RequestBody LoginDTO` |

### 测试请求模板
对于提取到的复杂接口，生成如下形式的伪造 HTTP 请求：
```http
POST /api/login HTTP/1.1
Host: {{host}}
Content-Type: application/json

{
  "username": "admin",
  "password": "password123"
}
```

## ⚠️ 注意事项
- **不忽略任何端点**: 即使是内部调用的 `/internal/` 路由或者 Actuator 等框架自带路由，只要在源码中能静态分析出，就必须一并列出。
- **动态路径处理**: 路径中包含正则表达式或变量时（如 `/users/{id:\d+}`），保持原始格式并注明其为动态参数。

## 📚 参考资料说明
关于各框架的路由解析规则和官方文档，请参阅 `references/framework_docs.md`。