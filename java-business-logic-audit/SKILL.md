---
name: "java-business-logic-audit"
description: "Java 业务逻辑漏洞专属审计工具。重点排查越权漏洞（IDOR）、并发漏洞（竞态条件）、验证码绕过、支付与密码找回等与技术组件无关，但严重影响业务安全的逻辑缺陷。"
---

# Java Business Logic Audit (业务逻辑漏洞安全审计)

传统的 SAST 工具和单纯的代码搜索很难发现“业务逻辑漏洞”，因为这类漏洞的代码在语法上完全正确，也没有直接调用危险的 Sink（如 `Runtime.exec`），而是**业务流程设计**存在缺陷。
本技能旨在指导 AI 像高级安全研究员一样，深入理解代码的业务意图，排查逻辑盲区。

## 🎯 触发场景 (When to Invoke)

- 用户要求检查“越权漏洞”、“并发漏洞”、“支付漏洞”、“逻辑漏洞”时。
- 审计包含 `UserController`, `OrderController`, `PaymentController`, `AccountController` 等核心业务代码时。
- 结合 `java-route-mapper` 提取出的高危敏感路由进行专项深度研判。

## 🕵️‍♂️ 核心审查工作流 (Review Workflow)

### 1. 越权漏洞审查 (IDOR - Insecure Direct Object Reference)
**核心逻辑**：代码中是否仅仅验证了“用户已登录”，却忘记了验证“被操作的数据是否属于该用户”。
- **水平越权**：
  - 定位类似 `getUserInfo(Long userId)`, `updateOrder(String orderId)` 的接口。
  - **追踪 Service 层**：检查在执行 DAO 层的 `select` 或 `update` 时，是否**强行将当前 Session 中的 `userId` 作为过滤条件**。
  - 🚨 *危险信号*：`select * from orders where order_id = #{orderId}` (只有 ID，无 User 绑定)。
  - ✅ *安全模式*：`select * from orders where order_id = #{orderId} and user_id = #{currentUserId}`。
- **垂直越权**：
  - 检查普通用户能否通过猜测或枚举 URL 访问到后台管理接口（如从 `/api/user/info` 猜到 `/api/admin/info`），结合 `java-auth-audit` 检查路由拦截配置。

### 2. 并发与竞态条件审查 (Race Conditions / Concurrency)
**核心逻辑**：在多线程环境下，对敏感数据（如余额、库存、积分）的扣减操作是否安全。
- **定位敏感操作**：搜索 `balance -`, `stock -`, `update account`, `ReentrantLock`, `@Transactional`。
- **检查加锁机制**：
  - 是否存在“先查后写”（Read-Modify-Write）的模式？（例如：先查库存 `if(stock > 0)`，再做 `stock = stock - 1`）。
  - 如果存在，必须检查这中间是否加了**悲观锁**（如 `select ... for update`）或**乐观锁**（如 `update ... where version = v`），或者使用了 Redis/Redisson 分布式锁。
  - 🚨 *危险信号*：使用了 `@Transactional` 但没有加任何锁，导致高并发下库存超卖。

### 3. 验证码与多步流程绕过 (Captcha & Multi-step Bypass)
- **验证码复用**：
  - 定位校验验证码的代码（如登录、注册、找回密码）。
  - 🚨 *危险信号*：在校验验证码正确后，**没有立即从 Session 或 Redis 中删除该验证码**，导致攻击者可以带着同一个正确的验证码无限次爆破密码。
- **多步流程跳跃**：
  - 对于密码找回（Step1: 验证手机号 -> Step2: 验证短信 -> Step3: 重置密码）。
  - 检查 Step3 是否强校验了 Step2 的完成凭证（如一个一次性的 Token）。如果仅凭手机号就能直接调用 Step3 接口，即为严重漏洞。

### 4. 数据一致性与金额篡改 (Data Consistency / Payment Tampering)
- **前端数据不可信**：
  - 定位下单或支付接口。
  - 🚨 *危险信号*：Controller 接收前端传入的 `price` 或 `amount` 参数并直接落库。
  - ✅ *安全模式*：前端仅传入 `productId`，后端根据 ID 重新从数据库查询价格。

## 📝 审计报告规范 (Audit Report Format)

**强制执行**: 输出报告时，必须严格遵守全局审计报告输出规范：`../shared/references/audit_reporting_standards.md`。

报告应特别针对逻辑漏洞的特点进行说明：
1. **业务场景描述**：简述该代码原本的业务意图（如“这是一个积分兑换接口”）。
2. **逻辑缺陷说明**：清晰指出开发者在设计时忽略了什么（如“未校验操作对象归属”或“未处理并发扣减”）。
3. **调用链必须展示**：展示从 Controller 接收参数到 Service 发生逻辑错误的完整代码行号链接。

## 📚 参考资料说明
关于更多业务逻辑漏洞的实战 Checklist（提取自 HackTricks 与实战经验），请参阅 `references/logic_vulnerability_patterns.md`。
