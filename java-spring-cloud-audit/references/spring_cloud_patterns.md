# Spring Cloud 漏洞模式与架构缺陷库 (Spring Cloud Vulnerability Patterns)

## 1. Spring Cloud Gateway SPEL 注入 (CVE-2022-22947)

### 漏洞原理
当 Spring Cloud Gateway 开启了 Actuator 端点，并且未对管理端点进行访问控制时，攻击者可以通过 `/actuator/gateway/routes` 接口动态添加路由。如果在过滤器（Filter）的参数中插入了恶意的 SPEL 表达式（如 `#{T(java.lang.Runtime).getRuntime().exec("id")}`），当路由被触发时，该表达式会被解析执行，导致远程代码执行（RCE）。

### 审计检查点
1.  **Actuator 配置** (`application.yml`):
    ```yaml
    management:
      endpoint:
        gateway:
          enabled: true # 高危，如果此时没有鉴权
      endpoints:
        web:
          exposure:
            include: "*" # 极度危险
    ```
2.  **自定义 Filter 滥用 SPEL**:
    搜索代码中是否有 `SpelExpressionParser` 解析了来自 Header 或 URL 的动态内容。

## 2. 微服务鉴权透传绕过 (Header Spoofing)

### 漏洞原理
在微服务架构中，网关负责鉴权并解析出用户信息（如 `userId`），然后通过自定义 HTTP Header（如 `X-User-Id`）传递给后端微服务。如果后端微服务**只信任**这个 Header，且**没有检查**该请求是否真的来自网关，攻击者就可以通过直接访问微服务并伪造 Header 来绕过鉴权。

### 审计检查点
1.  **内部 Controller**:
    ```java
    @GetMapping("/inner/user/info")
    public UserInfo getInfo(@RequestHeader("X-User-Id") String userId) {
        // 直接信任了 Header，如果没有网关 IP 白名单或内部 RPC 签名，极易被绕过
        return userService.findById(userId);
    }
    ```
2.  **网关清洗遗漏**:
    检查网关的 GlobalFilter 是否在将请求转发给下游之前，**清除了**外部客户端传入的伪造 Header。
    - **安全做法**:
      ```java
      // 网关过滤器中：
      request.mutate().headers(httpHeaders -> {
          httpHeaders.remove("X-User-Id"); // 先清除外部伪造的
          httpHeaders.add("X-User-Id", verifiedUserId); // 再添加自己校验后的
      }).build();
      ```
    - 如果网关没有 `remove` 操作，外部伪造的 `X-User-Id` 可能会被透传给后端。

## 3. Eureka/Nacos 元数据投毒与反序列化

### 漏洞原理
注册中心不仅存储服务的 IP 和端口，还存储 `metadata`。如果应用在获取实例元数据时进行了解析（如某些老版本的 Ribbon 或 Eureka Client 包含反序列化逻辑），攻击者通过未授权访问注册中心，注册一个带有恶意 payload 元数据的假服务，可能会触发反序列化漏洞。

### 审计检查点
检查配置中是否对注册中心实施了强认证：
```yaml
# 不安全的配置
eureka:
  client:
    serviceUrl:
      defaultZone: http://eureka-server:8761/eureka/

# 安全的配置 (带认证)
eureka:
  client:
    serviceUrl:
      defaultZone: http://admin:password123@eureka-server:8761/eureka/
```
