

# 🛡️ Java Security Audit Skills Pack

**为 AI Agent 打造的 Java 代码安全审计专家级技能库**


</div>

这是一套专为AI Agent 打造的 **Java 代码安全审计专家级技能库**。它结合了传统静态代码扫描（SAST）的严谨性和大语言模型（LLM）的推理能力，旨在帮助开发者和安全研究员快速、精准地发现 Java Web 项目中的潜在漏洞。

## 🌟 核心特色

- **🤖 零配置开箱即用**: 只需在 Trae 中一句自然语言指令，AI 即可自动理解项目结构并开始多线程审计。
- **📦 无源码/黑盒审计**: 面对生产环境打包后的 `WEB-INF/classes` 目录或 `.jar` 文件，内置的批量反编译引擎（CFR）会自动将其还原为标准的 `.java` 目录结构。
- **🌲 主动 AST 预扫描**: 内置基于 `Tree-sitter` 的 Python 脚本，在审计初期主动对整个项目进行大盘俯瞰。
- **✂️ 抗幻觉代码切片**: 面对动辄数千行的复杂 `ServiceImpl`，自动调用 AST 切片工具提取指定方法、成员变量和导入列表，极大降低 Token 消耗并消除 AI 幻觉。
- **⚡ 自动化核心提取**:
  - **Spring 路由自动化提取**: 秒级提取所有 `@RequestMapping` 等注解及 Controller **方法参数类型**，生成精准的 API 字典与输入参数特征（区分用户可控输入与内部注入对象）。
  - **MyBatis SQL 风险自动化提取**: 专门的 XML 解析脚本直击 `.xml` Mapper，精准抓取 `<select>`, `<update>` 等标签内的 `${}` 风险点。
- **🔗 深度数据流追踪 (Source to Sink)**: 摒弃传统的“关键词匹配”扫描方式，强制 AI 在复杂的多层链路（包含接口与实现类、DTO 解包）中追踪数据的真实流向。并引入“类型溯源法”解决同名函数的极端歧义。
- **🔍 工程化组件扫描 (SCA)**: 针对 `pom.xml`，内置了基于 Python XML 解析的工程化扫描脚本，彻底解决大模型在处理 `${version}` 变量替换时的“睁眼瞎”问题。
- **✅ 全局防误报与自我校验**: 统一的 `shared` 规则库约束了所有子技能的行为，并在生成报告前强制执行“逻辑闭环灵魂三问”，确保审计结果的准确性和极低的误报率。

***

## 🚀 审计流水线 (Audit Pipeline)

为了最大化审计效率和准确率，本技能库采用**多阶段渐进式流水线**设计。在启动 `java-ai-code-audit-pipeline` (主控节点) 时，AI 将严格按照以下先后顺序编排任务：

### Phase 1: 基础设施与信息收集 (Reconnaissance)

*这是所有审计的基础，必须最先执行。*

1. **`java-vuln-scanner`**: 扫描 `pom.xml`，锁定老旧的高危组件（如 Fastjson, Shiro），为后续的专精扫描提供方向。
2. **`java-route-mapper`**: 运行 AST 提取脚本，秒级生成全站 API 路由地图（`routes.json`），包含完整的路径、请求方法以及带类型的**参数列表**，明确所有攻击入口（Source）。

### Phase 2: 全局安全配置审查 (Global Configuration)

*在深入业务代码前，先看“大门”是否关紧。*
3\. **`java-auth-audit`**: 检查 Spring Security / Shiro 的拦截器配置，比对 Phase 1 提取的路由地图，找出 0-click（未授权即可访问）的暴露接口。
4\. **特定架构审计** (按需触发): 如果是微服务，调用 `java-spring-cloud-audit`；如果是 Shiro，调用 `java-shiro-audit`。

### Phase 3: 漏洞专精深度扫描 (Deep Scanning)

*带着前两个阶段收集的靶标，开始并发深挖具体代码。*
5\. **`java-sql-audit`**: 运行 MyBatis 提取脚本，找出所有 `${}` 拼接点（Sink）。
6\. **`java-business-logic-audit`**: 盯着核心 Controller，排查 IDOR 越权、无锁并发、支付等业务逻辑漏洞。
7\. **其他专精技能**: `java-xxe-audit`, `java-file-audit`, `java-deserialization-audit` 并行扫描。

### Phase 4: 链路确诊与防误报 (Validation)

*发现 Sink 后，必须证明其可被利用。*
8\. **`java-route-tracer`**: 从 Phase 3 发现的 Sink 逆向追踪到 Phase 1 的 Source（Controller），证明外部数据可达且未被有效净化。严格区分外部可控输入与 Spring 内部对象（如 `HttpServletRequest`, `Model`）。

### Phase 5: 规范化输出 (Reporting)

最终输出带有详细调用链（精确到文件路径和行号）、鉴权要求和可执行 POC 的标准化安全报告。

***

## 🛠️ 技能清单 (Available Skills)

本套件由 **1个主控调度技能** + **12个专精子技能** + **1套全局共享规则与工具** 组成。

### 核心调度器

- ⚙️ **`java-ai-code-audit-pipeline`**: **全自动流水线执行器**。它是整个技能库的大脑，负责编排所有的子技能。当你输入“帮我用流水线审计一下这个项目”、“一键审计这几个 jar 包”或“扫描这个 WEB-INF/classes 目录”时，它会被唤醒，并严格按照 **4阶段审计流水线**（反编译/提取、专精扫描、链路确诊、规范化报告），自动分配具体的专精子技能（如发现 MyBatis 就调 `java-sql-audit`）。它专门针对源码、`.jar` 包或包含 `.class` 文件的生产环境产物设计，完全隔离于外部全局同名组件，确保只使用本目录下的专精工具。最终将所有子技能的结果汇总、验证防误报，并输出最终报告。

### 专精子技能 (Specialized Sub-Skills)

| 技能名称                                | 关注领域       | 适用场景 / 触发指令示例                              |
| :---------------------------------- | :--------- | :----------------------------------------- |
| 🗺️ **`java-route-mapper`**         | API 接口梳理   | “帮我提取项目里所有的接口和参数”                          |
| 💉 **`java-sql-audit`**             | SQL 注入排查   | “检查 MyBatis/Hibernate 里有没有 SQL 拼接”         |
| 🔑 **`java-auth-audit`**            | 鉴权与越权分析    | “看看 Spring Security 配置有没有绕过风险”             |
| 💼 **`java-business-logic-audit`**  | 业务逻辑与越权    | “检查这个下单接口有没有并发问题，修改订单有没有越权”                |
| 📦 **`java-xxe-audit`**             | XML 外部实体注入 | “检查 Excel/PDF/XML 解析器是否禁用了 DTD”            |
| 📁 **`java-file-audit`**            | 文件操作安全     | “检查上传接口有没有白名单，下载有没有路径穿越”                   |
| 💣 **`java-deserialization-audit`** | 反序列化漏洞     | “扫描一下 Fastjson 和 readObject 的使用”           |
| 👻 **`java-memshell-audit`**        | 内存马与后门排查   | “检查有没有恶意的 Filter 注册或自定义 ClassLoader”       |
| 🛡️ **`java-shiro-audit`**          | Shiro 安全专题 | “检查 Shiro 密钥是否硬编码，有没有权限绕过漏洞”               |
| ☁️ **`java-spring-cloud-audit`**    | 微服务架构安全    | “排查 Spring Cloud Gateway 路由注入和内部 Feign 鉴权” |
| 🔍 **`java-route-tracer`**          | 调用链追踪辅助    | (通常由其他技能调用) 跨越接口追踪参数流向                     |
| 📊 **`java-vuln-scanner`**          | 第三方组件漏洞    | “扫描 pom.xml，匹配高危组件库”                       |

***

## 📁 目录结构

```text
.trae/skills/
├── shared/                                 # 🌍 全局共享规则与工具库
│   ├── scripts/
│   │   ├── batch_ast_scanner.py            # 全局 AST 预扫描工具
│   │   ├── batch_decompile_mapper.py       # 无源码目录批量反编译工具
│   │   ├── auto_decompile.py               # 单文件/JAR包极速反编译工具
│   │   └── ast_extractor.py                # 抗幻觉单文件方法切片工具
│   └── references/
│       ├── taint_analysis_rules.md         # 强制的数据流追踪与可控性判定准则
│       ├── audit_reporting_standards.md    # 统一的 Markdown 漏洞报告格式 (要求 POC 与行号)
│       └── ...
├── java-ai-code-audit/                     # 🧠 主调度技能
├── java-route-mapper/                      # 🗺️ 路由与参数提取器
│   └── scripts/
│       └── spring_route_extractor.py       # Spring 路由自动化提取脚本 (支持 AST 与正则回退)
├── java-business-logic-audit/              # 💼 业务逻辑与越权排查
├── java-sql-audit/                         # 💉 SQL 注入排查
│   └── scripts/
│       └── mybatis_sql_extractor.py        # MyBatis XML ${} 风险自动提取脚本
├── java-vuln-scanner/                      # 📊 SCA 扫描器
│   └── scripts/
│       └── pom_parser.py                   # 解决 pom 变量替换的 XML 解析脚本
└── ... (其他专精子技能)
```

***

## ⚙️ 环境依赖

在开始之前，确保你的系统安装了 Python 3.8+，并安装以下依赖以支持 AST 解析和自动化脚本：

```bash
pip install tree-sitter tree-sitter-java
```

*(注意：如果你需要审查无源码的* *`.class`* *或* *`.jar`，请确保系统环境变量中配置了* *`javap`* *或下载了 CFR 反编译工具)*

***

## 🚀 快速开始

将本项目作为你的工作区，或将 `skills` 目录复制到你想要审计的 Java 项目根目录下。然后IDE导入成功后，在IDE 的对话框中输入以下任意指令：

**全量自动化体检：**

> *"请使用 java-ai-code-audit 帮我全面审计一下当前项目的安全漏洞。"*

**特定业务逻辑排查：**

> *"使用 java-business-logic-audit 检查一下* *`OrderController`* *里有没有水平越权或者并发扣减库存的漏洞。"*

**专项技术检查：**

> *"重点追踪一下* *`UserController.update`* *方法里的* *`avatarPath`* *参数，看看会不会导致路径穿越。"*

**享受 AI 安全专家的 Pair Programming 体验吧！**

**致谢**
https://github.com/RuoJi6/java-audit-skills
