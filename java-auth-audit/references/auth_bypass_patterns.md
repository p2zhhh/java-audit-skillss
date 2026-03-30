# 鉴权与越权漏洞识别规则库

本文档列出了在 Java 框架中常见的权限绕过和越权访问的代码模式。

## 1. 框架层面的鉴权绕过
### 1.1 Spring Security 绕过风险
- **URI 解析差异**:
  - 配置 `antMatchers("/admin/**").authenticated()`。
  - **风险**: 如果使用了 `RegexRequestMatcher`，或者使用了老版本的 Spring Security，攻击者可能通过构造 `/admin/.` 或 `/admin/a/../` 绕过校验。
- **过度放行的白名单**:
  - `permitAll()` 规则过于宽泛，例如将包含敏感接口的父目录整个放行。

### 1.2 Apache Shiro 绕过风险
- **经典的目录穿越绕过 (CVE-2020-1957 等)**:
  - Shiro 对 URL 的拦截规则（如 `/api/v1/user/*=anon`）。
  - **风险**: Tomcat/Spring 解析 URL 与 Shiro 解析 URL 存在差异。如请求 `/api/v1/user/a%2fa`，Spring 认为是合法路径，而 Shiro 可能因匹配不到而放行。

## 2. 自定义拦截器 (Interceptor/Filter) 缺陷
- **弱匹配逻辑**:
  - `if (request.getRequestURI().contains("/login")) return true;`
  - **攻击方式**: 访问 `/api/admin/deleteUser?param=/login` 即可绕过。
- **扩展名后缀放行**:
  - `if (uri.endsWith(".js") || uri.endsWith(".css")) return true;`
  - **攻击方式**: 访问 `/api/admin/deleteUser;.js` (利用 Matrix 变量或路径截断)。

## 3. 越权访问 (IDOR / Privilege Escalation)
### 3.1 水平越权 (Horizontal IDOR)
- **特征**:
  - Controller 接收 `id`, `orderId`, `userId` 等参数。
  - Service 层直接使用该 `id` 进行数据库更新/删除/查询，**未校验**该资源所属的 `userId` 是否等于 `Session.getCurrentUser().getId()`。

### 3.2 垂直越权 (Vertical Privilege Escalation)
- **特征**:
  - 管理员接口（如 `/admin/deleteUser`）上缺少 `@RequiresRoles("ADMIN")` 或 `@PreAuthorize("hasRole('ADMIN')")` 等注解。
  - 或者全局配置中未对 `/admin/**` 路径进行角色限制。