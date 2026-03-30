---
name: "java-spring-cloud-audit"
description: "Spring Cloud 微服务架构专属安全审计工具。重点排查 Spring Cloud Gateway 路由注入漏洞、Eureka/Nacos 未授权访问、以及微服务间内部调用鉴权缺失问题。"
---

# Java Spring Cloud Audit (微服务架构安全审计)

在微服务架构中，安全边界从单一的 Web 容器转移到了 API Gateway 和各个服务节点之间。本技能专门用于审查 Spring Cloud 组件配置缺陷、路由注入漏洞以及微服务内部调用（RPC）的鉴权盲区。

## 🎯 触发场景 (When to Invoke)

- 用户要求审查 "微服务架构安全"、"Spring Cloud Gateway 漏洞" 或 "服务间调用权限"。
- 全局审计时，如果在 `pom.xml` 中发现 `spring-cloud-starter-gateway`、`spring-cloud-starter-netflix-eureka-client`、`spring-cloud-starter-openfeign` 等依赖。

## 🕵️‍♂️ 审查工作流 (Review Workflow)

### 1. Spring Cloud Gateway 漏洞排查 (CVE-2022-22947 等)
API 网关是微服务的入口，其动态路由配置极易引发代码执行（SPEL 注入）或 SSRF。
- **动态路由配置检查**：
  - 检查项目是否启用了 Actuator 的 Gateway 端点 (`management.endpoint.gateway.enabled=true`) 且未做鉴权。这会导致攻击者通过 POST `/actuator/gateway/routes` 动态添加恶意的 SPEL 路由过滤器。
- **自定义 Filter 审查**：
  - 寻找实现了 `GlobalFilter` 或 `GatewayFilter` 的类。
  - **重点排查**：在 Filter 中是否直接读取了请求头或请求参数，并将其作为 SPEL 表达式执行（`ExpressionParser.parseExpression(userInput)`），这会导致直接的 RCE。
  - **降级/穿透排查**：检查鉴权 Filter 中是否存在对特定路径的“白名单”放行逻辑（如 `if(path.contains("/api/public/")) return chain.filter(...)`），并评估是否可以通过 `..;` 或其他技巧绕过。

### 2. 注册中心与配置中心未授权访问 (Registry & Config Server Audit)
- **Eureka / Nacos / Consul**：
  - 检查配置文件 `application.yml` 或 `bootstrap.yml` 中的注册中心地址配置。
  - 评估这些组件的服务端口（如 Eureka 的 8761，Nacos 的 8848）是否暴露在公网，且是否配置了基础的 Basic Auth 认证。如果没有配置认证（如 `eureka.client.serviceUrl.defaultZone` 中没有账号密码格式 `http://user:pass@host`），需记录为高危配置缺陷。

### 3. 微服务内部调用鉴权盲区 (RPC/Feign Call Authorization)
微服务常见的安全错觉是：“只要外部请求经过了网关鉴权，内部服务之间的调用就是绝对安全的。” 攻击者一旦攻破边缘服务，即可在内网横向移动。
- **Feign Client 审查**：
  - 查找 `@FeignClient` 注解的接口。
  - 检查内部 Controller 提供给 Feign 调用的端点（通常带有 `/inner/` 或 `/rpc/` 前缀），是否配置了内部鉴权拦截器。
  - **鉴权头透传风险**：检查 `RequestInterceptor` 是否盲目将前端传来的所有 Header（包括伪造的 `X-User-Id` 或 `X-Internal-Token`）直接透传给下游服务。
- **微服务鉴权白名单滥用**：
  - 检查底层服务的安全配置（如 `WebSecurityConfigurerAdapter`），是否对网关 IP 或特定网段直接配置了 `permitAll()`。如果是，需提醒可能存在 SSRF 打击内网的风险。

## 📝 审计报告规范 (Audit Report Format)

**强制执行**: 输出报告时，必须严格遵守全局审计报告输出规范：`../shared/references/audit_reporting_standards.md`。

报告应特别针对“网关层”与“内部服务层”分别给出结论：
1. **网关安全基线**：Actuator 暴露情况、路由注入风险评估。
2. **内部信任模型评估**：指出微服务之间是否存在“零信任”机制缺失（即内部调用无鉴权），并提供攻击场景（例如：攻击者利用服务 A 的 SSRF 直接调用服务 B 的高危无鉴权内部接口）。

## 📚 参考资料说明
关于 Spring Cloud Gateway 的 SPEL 注入特征及微服务鉴权绕过模式，请参阅 `references/spring_cloud_patterns.md`。
