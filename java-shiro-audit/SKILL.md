---
name: "java-shiro-audit"
description: "Apache Shiro 专属安全审计工具。重点排查 Shiro 权限绕过漏洞（CVE-2020-1957 等路由匹配差异）、默认密钥（RememberMe 反序列化漏洞）及不安全的 Session 管理配置。"
---

# Java Shiro Audit (Apache Shiro 专属安全审计)

Apache Shiro 是 Java 领域极其常用的认证与授权框架，但由于其历史架构问题，频繁爆出**权限绕过 (Auth Bypass)** 与 **反序列化 (Deserialization)** 漏洞。本技能专门用于深度审查基于 Shiro 的安全配置和实现代码。

## 🎯 触发场景 (When to Invoke)

- 用户明确要求检查 "Shiro 漏洞" 或 "Shiro 权限绕过"。
- 在全局审计 (`java-ai-code-audit`) 中，如果发现项目中引入了 `shiro-core` 或 `shiro-spring` 依赖，必须调用本技能进行专项检查。
- 审计包含 `ShiroConfig`, `ShiroFilterFactoryBean` 或自定义 `Realm` 的代码时。

## 🕵️‍♂️ 审查工作流 (Review Workflow)

### 1. 组件识别与版本提取 (Component Detection)
- 优先查看 `pom.xml` 或 `build.gradle`，提取 Shiro 的具体版本号。
- **高危基线判断**：
  - 如果版本 `< 1.2.4`，极大概率存在经典的 RememberMe 默认密钥反序列化漏洞 (CVE-2016-4437)。
  - 如果版本 `< 1.5.3`，存在结合 Spring 动态路由的权限绕过漏洞 (CVE-2020-1957) 等。
  - *如果发现低版本，必须在报告中作为最高优先级风险指出。*

### 2. RememberMe 反序列化审查 (RememberMe Deserialization Audit)
- 搜索项目中配置 `CookieRememberMeManager` 的代码位置（通常在 `ShiroConfig.java` 中）。
- **硬编码密钥检查**：
  - 检查 `setCipherKey()` 方法。如果传入的是硬编码的 Base64 字符串（如著名的 `kPH+bIxk5D2deZiIxcaaaA==`），则是**严重漏洞**。
  - 如果没有显式调用 `setCipherKey()`（即使用默认随机生成），在单机环境下安全，但在集群环境下会导致 Session 验证失败，需提醒用户。
- **密钥来源分析**：如果密钥来源于配置文件（如 `@Value("${shiro.key}")`），必须去对应的 `application.yml` 或 `properties` 中确认该值是否为众所周知的弱密钥。

### 3. 权限绕过漏洞审查 (Auth Bypass / Routing Mismatch Audit)
这是 Shiro 最复杂的审计点，主要源于 Shiro 的 AntPathMatcher 与 Spring 的路由解析规则存在差异（如对待 `/`, `;`, `%2e` 的不同处理）。

- 定位 `ShiroFilterFactoryBean` 的 `setFilterChainDefinitionMap()` 配置。
- **`/` 绕过检查**：检查是否存在类似 `/admin/* = authc` 的配置。在老版本中，攻击者访问 `/admin/1` 会被拦截，但访问 `/admin/1/`（末尾加斜杠）会被 Spring 接受（Spring 认为等同于 `/admin/1`），而 Shiro 认为不匹配 `/admin/*`，从而导致**权限绕过**。
- **`;` (分号) 绕过检查**：检查 Spring Boot 版本。Spring 在处理 URL 路径参数（Matrix Variables）时，会将 `;` 后面的内容截断。如果攻击者访问 `/admin/page;bypass`，Shiro 看到的是全路径可能放行，但 Spring 实际路由到了 `/admin/page`。
- **防御措施验证**：检查项目是否配置了自定义的 `PathMatchingFilter` 或重写了 Spring 的 `StrictHttpFirewall` 来拦截恶意的路径字符。

### 4. 自定义 Realm 审计 (Custom Realm Audit)
- 定位继承了 `AuthorizingRealm` 的类。
- **SQL 注入风险**：检查 `doGetAuthenticationInfo` (认证) 和 `doGetAuthorizationInfo` (授权) 方法。如果从数据库查询用户或权限时使用了拼接 SQL，会引发高危 SQL 注入（因为认证过程往往是未授权用户可触达的第一道门）。此步骤请遵循 `../shared/references/taint_analysis_rules.md`。

## 📝 审计报告规范 (Audit Report Format)

**强制执行**: 输出报告时，必须严格遵守全局审计报告输出规范：`../shared/references/audit_reporting_standards.md`。

报告结构应包含：
1. **Shiro 组件版本分析**：明确指出当前版本及存在的历史 CVE 风险。
2. **密钥管理安全**：指出 RememberMe 密钥的配置情况（硬编码、动态生成、配置读取）。
3. **路由规则匹配风险**：详细列出可能存在绕过风险的 `filterChainDefinitionMap` 配置及绕过 Payload 示例（如 `/api/admin/page;/..`）。

## 📚 参考资料说明
关于 Shiro 常见的弱密钥列表及经典绕过 Payload（如 CVE-2020-1957, CVE-2020-11989），请参阅 `references/shiro_vulnerability_patterns.md`。
