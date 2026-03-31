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

### Phase 2: 危险接口过滤与 Agent 语义级安全校验 (Safe Pruning)
为了防止在后续可能的动态发包/逻辑推演中破坏系统数据，必须对提取到的路由进行严格的“破坏性动作”过滤。
**【优先级规则】：Agent 的语义确认拥有绝对的最高优先级（具有最终否决权和豁免权），脚本仅作为辅助打标工具。**

1. **脚本基础过滤 (Warning Flagger)**: Python 脚本会基于关键字黑名单（`delete`, `del`, `remove`, `update`, `modify`, `edit`, `reset`, `clear`, `drop`, `insert`, `add`, `create`）进行一轮粗筛，并给这些接口打上 `[DANGEROUS]` 标签。
2. **【关键】Agent 语义确认 (Semantic Safety Check)**: 
   - 脚本的正则可能会产生误报（例如 `/api/order/getDeliveryStatus` 被误打标为 `del`），也可能会产生漏报（例如一个叫 `/api/user/status` 的接口其实是用来封禁用户的）。
   - **Agent 的最终裁决**：
     - **豁免权**：如果脚本标记了某个接口为危险，但 Agent 审阅源码后发现它只是一个纯粹的查询接口（如 `getDeliveryStatus`），Agent **可以推翻脚本的结论，将其恢复为安全的靶点进行测试**。
     - **否决权**：如果脚本放行了某个接口，但 Agent 审阅源码发现其内部存在 `mapper.delete()`, `repository.save()`, `updateStatus()` 等修改数据库状态的操作，Agent **必须立刻否决，终止对该接口的 Fuzzing 尝试**。

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
**[H-LOGIC-001] 基于 ID 串联的水平越权与高危信息泄露**
- **漏洞类型**: IDOR / 敏感信息泄露
- **靶点接口 (Sink)**: `GET /api/v1/user/profile`
- **攻击链路 (ID Chain)**:
  1. **Step 1 (获取靶标 ID)**: 通过无鉴权接口 `GET /api/v1/public/comments` 批量收集到了多个 `userId` (如 `10086`)。
  2. **Step 2 (越权获取详情)**: 将收集到的 `userId` 填入靶点接口进行查询。
- **漏洞利用证明 (Proof of Concept)**:
  - **发包参数**: `GET /api/v1/user/profile?userId=10086`
  - **泄露的敏感数据**:
    ```json
    {
      "userId": "10086",
      "password_hash": "e10adc3949ba59abbe56e057f20f883e",
      "phone": "13812345678",
      "idcard": "11010519900101XXXX"
    }
    ```
- **修复建议**: 在 `UserProfileController.java` (Line 88) 中增加鉴权拦截，或者剔除 DTO 中的敏感字段。