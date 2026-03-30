---
name: "java-auth-audit"
description: "Java 鉴权机制与越权漏洞审查工具。智能识别 Spring Security、Shiro 及自定义拦截器，评估访问控制缺陷。当需要检查接口权限、发现未授权访问或越权风险时调用。"
---

# Java Auth Audit (Java 鉴权与越权审查工具)

访问控制（Access Control）是 Web 应用安全的核心防线。本工具旨在通过静态分析 Java 代码库中的安全框架配置、拦截器（Interceptors）和过滤器（Filters），识别未授权访问（Unauthorized Access）和越权（IDOR / Privilege Escalation）漏洞。

## 🎯 触发场景 (When to Invoke)

- 用户要求检查项目中的 “越权漏洞”、“权限绕过” 或 “未授权访问” 时。
- 需要梳理系统中的鉴权逻辑（如 JWT, Spring Security, Apache Shiro）时。
- 作为 `java-ai-code-audit` 流水线中针对业务逻辑安全审查的重要环节。

## 🛡️ 鉴权机制识别与审查 (Authentication & Authorization Review)

1. **安全框架与配置分析 (Security Framework Detection)**
   - **Spring Security**: 寻找继承 `WebSecurityConfigurerAdapter` 或配置了 `SecurityFilterChain` 的类。审查 `antMatchers().permitAll()` 是否过度放开了敏感接口。
   - **Apache Shiro**: 查找 `ShiroFilterFactoryBean` 或 `shiro.ini`，审查过滤链定义（如 `anon`, `authc`, `roles`, `perms`），排查是否存在类似 `/api/v1/user/*=anon` 导致 `/api/v1/user/a%2fa` 绕过的已知风险。
   - **JWT / OAuth2**: 查找 token 解析与校验逻辑，确认是否验证了签名（Signature），是否校验了过期时间（Expiration）。

2. **自定义拦截器分析 (Custom Interceptor/Filter Analysis)**
   - 寻找实现了 `HandlerInterceptor` (Spring MVC) 或 `Filter` (Servlet) 的类。
   - 检查 `preHandle()` 或 `doFilter()` 方法中，是否包含对用户登录状态（Session/Token）的校验逻辑。
   - **重点检查绕过点**: 分析拦截器中排除路径（Exclude Paths）的逻辑，如 `if(request.getRequestURI().contains("/login")) return true;`，这种简单的 `contains` 或 `endsWith` 极易被利用（例如 `/api/sensitive?param=/login`）。

3. **越权漏洞排查 (IDOR / Privilege Escalation)**
   - **水平越权 (Horizontal Privilege Escalation)**: 
     - 在 Controller 或 Service 层，寻找接收了类似 `userId`, `orderId` 等参数的方法。
     - **核心判定**: 检查在执行数据查询/更新前，是否校验了当前操作的实体所属的 `userId` 与当前登录用户的 `Session userId` 是否一致。
   - **垂直越权 (Vertical Privilege Escalation)**: 
     - 检查普通用户的操作接口是否缺少 `@PreAuthorize("hasRole('ADMIN')")` 或 `@RequiresRoles("admin")` 等角色注解限制。

## 📝 审计报告规范 (Audit Report Format)

**强制执行**: 当发现权限相关风险时，必须严格遵守全局审计报告输出规范：`../shared/references/audit_reporting_standards.md`。

在报告中，除了标准字段外，还需额外提供**绕过 Payload (可选)**: 如果发现拦截器绕过，提供示例（如 `GET /api/user/info;a.js`）。

## 💡 AI 分析策略

- **关注白名单与黑名单**: 安全配置通常推荐使用“默认拒绝（Deny All）+ 白名单放行”策略。如果发现系统采用的是黑名单拦截策略，应重点提醒存在遗漏风险。
- **注解与实际执行的差异**: 检查带有鉴权注解（如 `@RequiresPermissions`）的方法，确认 AOP 拦截器是否正常开启和生效。如果 AOP 配置错误，注解可能形同虚设。
- **结合全局分析**: 在报告漏洞前，参考 `../shared/references/audit_reporting_standards.md` 排除存在其他全局过滤器的误报。

## 📚 参考资料说明
关于 Spring Security 等框架的配置与最佳实践，请参阅 `references/access_control.md`。
常见的权限绕过手法与越权代码特征，请参考 `references/auth_bypass_patterns.md`。
**全局共享规范**: 数据流追踪与报告格式必须遵守 `../shared/references/` 下的规则文档。