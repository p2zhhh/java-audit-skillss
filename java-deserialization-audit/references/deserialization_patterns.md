# Java 反序列化漏洞识别与防御规则

本规则库总结了各类反序列化库的高危调用特征、防御写法以及数据流可控性（Source to Sink）的判断标准。

## 0. 数据流可控性判定 (Taint Analysis)
发现反序列化 Sink 后，必须判断其输入数据（Taint）的来源：
- **高危 (完全可控)**:
  - 来源于 Controller 的入参（如 `@RequestBody String json`, `byte[] data`）。
  - 来源于原生的 `HttpServletRequest.getInputStream()` 或 `getParameter()`.
  - 来源于未经鉴权的 RPC 接口入参（如 Dubbo, RMI）。
- **中危 (间接/条件可控)**:
  - 来源于数据库查询结果（需判断数据入库时是否可被攻击者控制，即“二次反序列化注入”）。
  - 来源于消息队列（如 Kafka, RabbitMQ），取决于消息生产者是否可信。
- **安全 (不可控)**:
  - 数据完全在后端生成，或来源于本地受保护的配置文件（如 `application.yml` 的正常解析）。

## 1. 原生 Java 反序列化
### 1.1 危险特征 (Sinks)
- `ObjectInputStream.readObject()`
- `ObjectInputStream.readUnshared()`
- `XMLDecoder.readObject()`
- `java.rmi.server.ObjID.readObject()` (RMI 场景)

### 1.2 防御特征 (Mitigations)
- **JEP 290**: 
  - 代码层面: `ObjectInputFilter.Config.setObjectInputFilter(ois, filter)`
  - JVM 层面: 启动参数包含 `-Djdk.serialFilter=...`
- **重写 `resolveClass`**: 自定义 `ObjectInputStream` 子类并重写 `resolveClass` 方法，实现类名白名单校验。

## 2. Fastjson 反序列化
Fastjson 的漏洞主要集中在 AutoType 机制上。

### 2.1 危险特征
- `JSON.parse(jsonString)`
- `JSON.parseObject(jsonString)` (如果未指定明确的期望类，或者开启了 Feature.SupportNonPublicField)
- 开启了 AutoType: `ParserConfig.getGlobalInstance().setAutoTypeSupport(true)`

### 2.2 防御特征
- 升级到 1.2.83 或以上版本（或迁移到 Fastjson2）。
- 开启 SafeMode: `ParserConfig.getGlobalInstance().setSafeMode(true)` (完全禁用 AutoType)。

## 3. Jackson 反序列化
Jackson 相对安全，但如果开启了多态类型处理（Polymorphic Type Handling），则可能产生漏洞。

### 3.1 危险特征
- 全局开启默认类型: `ObjectMapper.enableDefaultTyping()`
- 注解滥用: 在类或字段上使用 `@JsonTypeInfo(use = JsonTypeInfo.Id.CLASS)` 且未对传入类型进行限制。

### 3.2 防御特征
- 避免使用 `enableDefaultTyping`。
- 必须使用多态时，配置严格的白名单验证器: `BasicPolymorphicTypeValidator.builder().allowIfBaseType(MyBaseClass.class).build()`。

## 4. XStream 反序列化
### 4.1 危险特征
- `XStream.fromXML(xmlString)`
- 未配置任何权限校验机制（默认配置在早期版本是不安全的）。

### 4.2 防御特征
- 配置框架安全框架: `XStream.setupDefaultSecurity(xstream)`
- 添加白名单: `xstream.allowTypes(new Class[]{MyModel.class})`。

## 5. 常见 Gadget 链组件
审计时若发现以下依赖，需提高反序列化漏洞的风险评级：
- `commons-collections:3.2.1` 或 `4.0` (CC 链)
- `commons-beanutils` (CB 链)
- `rome`
- `javassist`
- `spring-core`, `spring-beans`, `spring-aop` (Spring 链)