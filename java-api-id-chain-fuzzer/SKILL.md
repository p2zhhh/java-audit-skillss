---
name: "java-api-id-chain-fuzzer"
description: "基于 ID 串联的 API 逻辑漏洞深度审计工具。支持源码及 jar/class 反编译，精准追踪 Controller 传参点，自动提取并利用泄漏的 ID 进行跨接口参数碰撞，挖掘越权与信息泄露漏洞。内建危险操作（删除/修改等）过滤机制。"
---

# Java API ID Chain Fuzzer (Java 接口 ID 串联模糊测试工具)

这是一种结合了 SAST（静态提取）与 DAST（动态发包串联）的高级白盒审计思路。在复杂的业务系统中，常常存在许多类似数据库主键的 ID（如 `userid`, `orderid`, `doc_id`）。如果从某些“查询/列表”接口中意外泄漏了这些 ID，攻击者便可利用这些 ID 去遍历其他需要相同参数的接口，从而导致水平越权（IDOR）或深度信息泄露。

本技能通过自动化代码反编译、精准参数追踪、以及基于语义的接口梳理，实现了这种“ID 串联”攻击路径的自动挖掘。

## 🎯 何时调用此 Skill (When to Invoke)
- 用户要求：“帮我找找越权漏洞”、“有没有 ID 遍历风险”、“审计接口逻辑漏洞”、“测试一下这些 ID 能不能串起来查到别的信息”。
- 在获取了项目的源代码、`.jar` 或 `.class` 文件，并希望寻找业务逻辑层的越权与信息泄露漏洞时。

## 🛠️ 核心工作流 (Execution Workflow)

### Phase 1: 资产解析与前置提取 (Asset Parsing & Reconnaissance)
1. **反编译支持**: 
   - 检查输入是源码、`.jar` 还是包含 `.class` 的目录（如 `WEB-INF/classes`）。
   - 若无源码，调用 `.trae/skills/shared/scripts/batch_decompile_mapper.py` 或 `auto_decompile.py` 将其转换为 Java 源码结构。
2. **路由与精准参数提取**:
   - 调用 `java-route-mapper` 或相关 AST 提取脚本，扫描所有的 `@RestController` 和 `@Controller`。
   - **【核心要求】**: 必须深入追踪到方法的具体参数定义。例如：`@RequestParam("userId") String userId`，或者封装在 `@RequestBody UserDTO` 中的 `userId` 字段。
   - 记录每个接口的 HTTP 方法（GET/POST 等）和完整的参数结构。

### Phase 2: 危险接口过滤与安全剔除 (Safe Pruning)
为了防止在后续可能的动态发包/逻辑推演中破坏系统数据，必须对提取到的路由进行严格的“破坏性动作”过滤。
1. **HTTP 方法过滤**: 原则上重点关注 `GET` 接口和部分仅用于查询的 `POST` 接口。
2. **语义黑名单剔除**: 
   - 如果接口 URL 路径或方法签名中包含以下关键字，**必须无条件剔除**，绝不进行串联尝试：
     `delete`, `del`, `remove`, `update`, `modify`, `edit`, `reset`, `clear`, `drop`, `insert`, `add`, `create`
   - 仅保留类似 `get`, `list`, `query`, `search`, `detail`, `info`, `export` 等纯读操作接口。

### Phase 3: ID 提取与关系网构建 (ID Chaining & Graphing)
1. **发现泄露源 (Leakage Sources)**:
   - 分析“列表/查询”类接口的返回值（通过分析 Controller 的返回实体类 DTO）。
   - 寻找可能返回包含 ID 集合的接口（例如：`GET /api/users/list` 可能会返回一批带有 `userId` 的对象）。
2. **寻找利用点 (Exploitation Sinks)**:
   - 在所有安全的读接口中，筛选出那些明确要求传入特定 ID 作为参数的接口。
   - 比如：`GET /api/user/detail?userId={id}`，或者 `POST /api/order/query` 且 body 中包含 `"userId": "{id}"`。
3. **构建串联关系图**:
   - 建立映射关系：`[接口A (Source) 泄漏了 X_ID]  --->  [接口B (Sink) 需要 X_ID 作为入参]`。

### Phase 4: 运行环境配置 (Runtime Configuration Setup)
如果需要执行真实的动态 Fuzzing（DAST 模式），必须提示用户提供以下必要的运行时环境参数：
- `--url`: 目标 API 的基准 URL (Base URL)。由于测试主要针对未授权暴露的接口进行逻辑探测，无需强制要求鉴权 Token 或自身 ID。

### Phase 5: 逻辑推演、敏感信息捕获与漏洞报告 (Fuzzing Logic & Reporting)
在明确了串联关系并执行发包后，Agent 必须深度审查返回的 HTTP 响应体：
1. **敏感信息自动识别**: 无论是在信息收集阶段（Source）还是越权利用阶段（Sink），一旦在 JSON 响应中发现类似 `password`, `phone`, `mobile`, `email`, `cardid`, `idcard`, `token` 等敏感字段，必须立即捕获！
2. **生成攻击链路与泄露报告**: 向用户输出一条完整的漏洞报告。
   - 指出哪个接口是受害者（Sink）。
   - 详细列出当时发送的具体参数（Payload）。
   - **【强制】**：必须将捕获到的敏感信息（如明文密码、身份证号）清晰地展示在报告中，作为漏洞存在的“铁证”。

## ⚠️ 运行时约束与安全红线
- **绝对的安全性**: 任何对数据库有写、删、改操作的接口，绝对禁止放入 ID 串联的执行或建议列表中。
- **参数溯源**: 参数必须精准溯源到用户明确可控的传参点（Query String, Form Data, JSON Body），不能是系统自动注入的上下文 ID（如从 Session/Token 解析出的不可篡改 ID）。

## 📝 报告输出格式示例
**[H-LOGIC-001] 基于 ID 串联的水平越权与信息泄露**
- **漏洞类型**: IDOR (Insecure Direct Object Reference) / 信息泄露
- **是否需要鉴权**: 需要基础登录权限
- **攻击链路 (ID Chain)**:
  1. **Step 1 (获取靶标 ID)**: 通过 `GET /api/v1/public/comments` 接口（无敏感权限），可以从响应的 `CommentDTO` 中批量收集到他人的 `userId`。
  2. **Step 2 (越权获取详情)**: 将收集到的 `userId` 填入 `GET /api/v1/user/profile?userId={id}`。
- **代码位置**: 
  - Source: `CommentController.java` (Line 45)
  - Sink: `UserProfileController.java` (Line 88) - 此处缺乏 `current_user_id == param_user_id` 的校验。
- **验证 PoC (联动)**:
  ```http
  // 1. 拿 ID
  GET /api/v1/public/comments HTTP/1.1
  Host: {{host}}
  
  // 2. 遍历越权
  GET /api/v1/user/profile?userId=10086 HTTP/1.1
  Host: {{host}}
  Authorization: Bearer {{my_token}}
  ```