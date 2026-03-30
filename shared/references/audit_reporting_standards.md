# 全局审计报告与反误报规范

为了确保 AI 代码审计结果的专业性、准确性和可读性，所有审计相关的 Skill 必须遵循以下报告输出标准和防误报原则。

## 1. 减少误报的最佳实践 (False Positive Reduction)

安全审计的价值在于精准，而非单纯的关键字堆砌。在判定漏洞并生成报告前，必须经过以下校验：

- **强制连通性验证**: 必须根据 `taint_analysis_rules.md`，证明发现的危险调用（Sink）接收了来自外部不受信的数据（Source）。**严禁将内部常量、硬编码配置标记为漏洞。**
- **执行审计质量自我校验**: 在准备输出结论前，必须阅读并回答 `audit_self_correction.md` 中的“逻辑闭环校验”三个灵魂拷问。如果发现有未闭环的逻辑，必须返回重新搜索或降级风险。
- **全局拦截器检查**: 在判定 Controller 或 Service 存在漏洞前，需搜索项目中是否存在全局的 `Filter` 或 `Interceptor`（例如：所有的 XSS 都已被全局包装的 `HttpServletRequestWrapper` 进行了 HTML 实体转义）。
- **执行上下文考量**: 例如组件扫描发现 Log4j2 低版本，需进一步检查应用是否实际使用了 `log4j-core` 的日志打印功能（如 `logger.error(userInput)`），若仅是引入但未调用或仅打印固定字符串，应降级为“组件依赖风险”而非“可直接利用的 RCE”。

## 报告结构模板 (Report Template)

每个被确认的漏洞必须遵循以下结构输出：

### 1. 漏洞基本信息 (Vulnerability Overview)
- **漏洞名称**: [如: Spring Cloud Gateway SPEL 注入]
- **危险等级**: [严重(Critical) / 高危(High) / 中危(Medium) / 低危(Low)]
- **漏洞类型**: [如: RCE, SQLi, SSRF, IDOR]
- **触发入口**: [如: `POST /actuator/gateway/routes`]

### 2. 漏洞位置与详情 (Vulnerability Details)
- **文件路径**: [完整的文件路径，最好带上行号范围]
- **危险代码/配置**: 展示直接导致漏洞的代码片段，并标记所在行号。

### 3. 可控性与触发条件 (Controllability & Preconditions) [核心]
- **Source to Sink 调用链**: 必须清晰列出从外部入口到危险操作的完整传递过程，**且每个节点都必须使用 Markdown 链接语法附带具体的文件路径和行号**。
  - *格式示例*:
    1. `Source`: [UserController.java:45](file:///path/to/UserController.java#L45) - `login(@RequestParam String username)`
    2. `Call`: [UserServiceImpl.java:88](file:///path/to/UserServiceImpl.java#L88) - `userDao.findByUser(username)`
    3. `Sink`: [UserMapper.xml:12](file:///path/to/UserMapper.xml#L12) - `select * from users where user = '${username}'`
- **鉴权要求 (Authentication & Authorization)**: 
  - **必须明确指出该漏洞的触发是否需要登录！** 
  - 是前台未授权（0-click）？还是需要普通用户登录？还是需要 Admin 权限？请结合路由配置（如 Shiro 拦截器、Spring Security 配置或 `@RequiresPermissions` 注解）进行分析。
- **环境或配置依赖**: 说明触发该漏洞是否依赖特定的 `application.yml` 配置（如 `management.endpoint.gateway.enabled=true`）或特定的 JDK 版本。

### 4. 漏洞复现 POC (Proof of Concept) [必须]
- **HTTP 请求模板**: 必须提供一个完整、格式正确且理论上可触发漏洞的 HTTP 报文。
- **Payload 说明**: 解释 Payload 中关键部分的作用。
```http
POST /api/vuln/endpoint HTTP/1.1
Host: {{target_host}}
Cookie: JSESSIONID={{your_valid_session_id}} # 如果需要登录，必须加上 Cookie 或 Token 头
Content-Type: application/json

{"cmd": "whoami"}
```

### 5. 修复建议 (Remediation)
- 提供针对性的、符合项目当前框架代码风格的修复方案（如给出具体的代码片段或配置修改建议）。

## 3. 审计结论分类
对于扫描到的疑似点，如果经过分析无法 100% 确认，请使用以下分类标签明确告知用户：
- 🔴 **确诊漏洞 (Exploitable)**: Source 到 Sink 链路完整，且无有效防御。
- 🟡 **潜在风险 (Needs Review)**: 发现高危 Sink，但由于调用链路极其复杂跨项目，或存在复杂的自定义正则过滤，AI 无法断定是否可绕过，需建议人工复核。
- 🟢 **安全/误报排除 (Safe/False Positive)**: 发现了危险特征，但已证实数据不可控或存在严密的过滤机制。这类情况**可选择不输出**，或在报告末尾的“已排除风险”中简要提及，以展示审计的全面性。