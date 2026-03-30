# Java 内存马注入与代码特征库

本文档总结了各类 Java 内存马（Memshell）的常见实现方式及其代码特征。

## 1. 传统 Servlet API 型内存马
此类内存马利用 Servlet 3.0+ 提供的动态注册 API，向运行中的上下文注入后门。

### 1.1 Filter 型内存马特征
- 强依赖 `javax.servlet.ServletContext` 或 `jakarta.servlet.ServletContext`。
- 关键方法调用: `addFilter(String filterName, Filter filter)`
- 恶意行为: 注入的 Filter 实现中，`doFilter` 方法通常会拦截特定请求（如带特定 Header 或 Parameter 的请求），并在内部执行 `Runtime.getRuntime().exec()`。

### 1.2 Servlet/Listener 型内存马特征
- 关键方法调用: `addServlet(...)`, `addListener(...)`
- 某些 Listener（如 `ServletRequestListener`）会在每次请求到达时触发，被滥用为后门入口。

## 2. Tomcat 特定型内存马
攻击者通过反射操作 Tomcat 的内部类来绕过一些安全限制。

### 2.1 FilterDef/FilterMap 反射注入
- 涉及类: `org.apache.catalina.core.StandardContext`, `org.apache.tomcat.util.descriptor.web.FilterDef`, `FilterMap`
- 特征: 大量使用反射获取 `StandardContext`，并调用 `addFilterDef`, `addFilterMapBefore`。

### 2.2 Valve 型内存马
Valve 是 Tomcat Pipeline 机制中的阀门。
- 涉及类: `org.apache.catalina.Valve`, `org.apache.catalina.Pipeline`
- 特征: 反射获取 `StandardContext` 的 `Pipeline`，并调用 `addValve(...)` 将恶意的 Valve 实例加入请求处理链中。

## 3. Spring 型内存马
针对 Spring MVC/Boot 框架的注入方式。

### 3.1 Controller/Interceptor 注入
- 涉及类: `org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping`
- 特征: 获取 Spring 的 ApplicationContext，动态调用 `registerMapping` 方法，将恶意方法注册为一个新的 API 路由。

## 4. JavaAgent 型内存马
利用 JVM 的 Instrument 机制，在类加载时或运行时动态修改字节码（如修改 `HttpServlet.service` 方法加入后门逻辑）。

- **特征**:
  - 存在 `premain(String, Instrumentation)` 或 `agentmain(String, Instrumentation)` 方法。
  - 调用 `Instrumentation.addTransformer(...)` 或 `retransformClasses(...)`。
  - 结合 ASM 或 Javassist 库进行字节码插桩。
  - 使用了 `com.sun.tools.attach.VirtualMachine.attach(pid)` (通常是注入工具的行为)。

## 5. 恶意类加载器 (ClassLoader)
攻击者常利用自定义 ClassLoader 将网络传输的恶意字节码加载到 JVM 中。
- **特征**:
  - 重写了 `java.lang.ClassLoader` 的 `defineClass(String name, byte[] b, int off, int len)` 方法。
  - 从 `request.getInputStream()` 或 `Base64.decode` 获取 `byte[]` 后直接传入 `defineClass` 并通过 `.newInstance()` 实例化。