# 全局数据流追踪与可控性分析规则 (Taint Analysis)

在进行任何类型的代码安全审计时，**仅发现危险的 Sink 点（如 `readObject`, `exec`, `new File()` 等）不足以判定漏洞存在，必须执行 Source 到 Sink 的数据流可控性分析。** 这是所有审计 Skill 必须遵守的核心原则。

## 1. 核心判定逻辑

漏洞是否成立 = **Sink 点存在** + **输入数据 (Source) 完全或部分受外部控制** + **数据在流转过程中未被有效过滤 (Sanitizer)**。

## 2. 污染源 (Source) 级别判定

在分析 Controller 或 RPC 入口点的方法参数时，必须严格区分**用户外部可控的输入参数**与**框架/系统内部注入的对象**。只有前者才能作为漏洞利用的 Source。

### 2.1 高危 (完全可控的外部输入)
如果数据来源于以下入口，且未经验证直接流入 Sink，则极大概率存在高危漏洞。**这些是攻击者可以直接构造 Payload 传入的地方**：
- **HTTP 显式请求参数**: 
  - Spring: `@RequestParam("id")`, `@PathVariable("userId")`, `@RequestBody UserDTO`, `@RequestHeader("X-Token")` 修饰的参数。
  - **没有注解的 POJO/DTO 对象**: 在 Spring MVC 中，如果不加注解的复杂对象（如 `User param`），Spring 默认会尝试用表单 URL-encoded 数据或 Query String 进行自动绑定，这也属于**完全可控**。
- **Servlet 原生外部输入**: `request.getParameter()`, `request.getInputStream()`, `request.getReader()`, `request.getCookies()`
- **未鉴权的 RPC 接口**: Dubbo, RMI, Hessian 等对外暴露的服务入参中的基础类型或反序列化对象。

### 2.2 绝对安全 (不可控内部对象 / 必须排除的 Source)
在审计方法的参数列表时，如果遇到以下类型的参数，**必须将其视为不可控对象（非 Source），攻击者无法直接篡改它们的值**。如果 Sink 的输入仅仅来自这些对象，则**直接判定为安全，属于误报**：
- **框架自动注入的内部上下文对象**:
  - `HttpServletRequest`, `HttpServletResponse`, `HttpSession` (注意：这些对象本身不可控，但从中提取的 `.getParameter()` 可控)。
  - Spring 上下文对象：`Model`, `ModelMap`, `ModelAndView`, `BindingResult`, `Errors`, `RedirectAttributes`。
  - 安全上下文：`Principal`, `Authentication` (通常代表已认证的当前用户信息，由拦截器从 Token 解析后注入，**绝不属于外部可控输入**)。
- **内部硬编码**: 代码中写死的常量字符串、固定路径（如 `new File("/tmp/app.log")`）。
- **受保护的本地配置文件**: 解析项目内部打包的 `application.yml`、`config.xml`。
- **系统环境变量**: `System.getenv()`, `System.getProperty()`。

### 2.3 中危 (间接/条件可控)

## 3. 净化机制 (Sanitizer) 评估
在 Source 流向 Sink 的路径中，必须检查是否存在安全防御机制：
- **白名单校验**: 如 `if(ALLOWED_LIST.contains(input))`，通常认为是安全的。
- **黑名单过滤**: 如 `input.replace("../", "")`，需评估是否可被绕过（如 `..././`）。
- **类型强转**: 如 `Integer.parseInt(input)`，如果目标 Sink 需要字符串，但中间经历了严格的类型转换，通常可阻断注入。

## 5. ⚠️ 强制工具使用规范：防幻觉与 Token 优化

在执行代码阅读和追踪时，**严禁使用普通的 `Read` 工具去直接读取超过 500 行的 Java 文件**，这会导致严重的 Token 上下文溢出和逻辑幻觉。

当你通过 `Grep` 或 `SearchCodebase` 找到了某个可疑的方法调用或漏洞 Sink 点所在的类和方法名后，**必须调用全局 AST 提取脚本**来精准获取上下文：

```bash
python .trae/skills/shared/scripts/ast_extractor.py <目标Java文件的绝对路径> [要追踪的方法名]
```

**该脚本将返回：**
1. 文件的所有 `import` 语句（用于消解同名类歧义）。
2. 类的所有成员变量声明（用于推断 `@Autowired` 注入的对象类型）。
3. 指定方法的**完整代码块**（如果提供了方法名）。

通过这种方式，你能以最小的 Token 消耗，获得最精准、无干扰的代码上下文进行分析。

## 6. 处理无源码的依赖包 (JAR/Class 分析)
如果在追踪过程中，数据流进入了某个没有源码的 `.class` 文件或第三方 `.jar` 包，**严禁直接停止追踪并报告无法分析**。
你必须遵守 `decompilation_guide.md` 中的规范，通过终端工具（如 `javap`, `unzip`, 或反编译工具）继续深入分析闭源逻辑。

1. **反向追踪 (Sink -> Source) 的精确匹配**: 
   - 扫描到敏感函数调用（Sink）后，必须**顺藤摸瓜，向上追溯方法调用者**。
   - **⚠️ 解决极端同名歧义 (类名/变量名/方法名均相同)**: 当面对复杂的业务代码时，甚至会出现不同包下的同名类（如 `com.a.FileUtils` 和 `com.b.FileUtils`）或完全相同的变量名调用。此时必须采用“**类型溯源法**”：
     1. **定位调用实例的声明**: 在调用点（如 `fileUtils.readFile()`），必须在当前文件中向上查找 `fileUtils` 这个变量的声明位置（如类的成员变量注入、方法局部变量或方法参数）。
     2. **提取真实类型**: 从声明处确认该变量的实际类型名称（如 `private FileUtils fileUtils;`）。
     3. **校验包路径 (Import Check)**: 拿到类型名后，去文件顶部的 `import` 列表中寻找该类型的全限定包名（Full Qualified Name）。如果当前文件所在的包与目标类在同一个包下，则可能没有显式的 `import`，需结合目录结构判断。
     4. **唯一性确认**: 只有当提取到的“全限定包名 + 类名 + 方法签名”与你正在追踪的目标 Sink 完全一致时，才能确认调用链路成立。绝对不能仅凭简单的正则字符串匹配就得出结论。
   - **⚠️ 穷举覆盖原则 (Exhaustive Search)**: 如果通过上述核对发现当前调用点是一个“同名不同类”的误报，**禁止就此停止追踪**。你必须返回搜索结果列表，**继续遍历和覆盖所有其他疑似的调用点**，直到找到真正的链路，或穷举完所有可能性后确认无有效链路为止。
2. **正向追踪 (Source -> Sink)**: 
   - 针对已知暴露的外部接口，追踪其接收的参数是否最终流入了敏感函数。同样需要遵守穷举分支的原则，防止遗漏 `if/else` 等条件分支中的漏洞点。
3. **跨越接口与实现 (Interface to Impl)**:
   - 当在 Controller 中看到调用了 `userService.update(param)` 时，如果 `UserService` 是一个接口，**严禁直接停止追踪**。
   - 必须去寻找 `UserService` 的实现类（如 `UserServiceImpl`），并进入其实际的 `update` 方法体内继续追踪数据流向。
4. **DTO/实体类的解包与装箱**:
   - 当参数被封装进一个 DTO（Data Transfer Object）或 Map 中传递时，必须追踪该对象的 `getter` 方法或 `get(key)` 操作。
   - 只有确认 DTO 中的恶意字段最终被取出并传入了 Sink，才能判定链路完整。
5. **处理隐式调用**:
   - 注意 AOP 切面、事件监听器（`ApplicationEventPublisher`）或反射调用打断的显式代码链路，必要时进行全局文本搜索。