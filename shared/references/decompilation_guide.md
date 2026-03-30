# 全局反编译与依赖包分析指南 (Decompilation & JAR Analysis)

在真实的企业级代码审计中，很多时候核心的漏洞逻辑并不在当前项目的 `.java` 源码中，而是隐藏在引入的闭源二方库或第三方 `JAR` 包中。
当追踪的数据流（Source）进入了一个没有源码的 `.class` 文件时，**禁止停止追踪**，必须执行反编译与字节码分析。

## 1. 识别编译文件入口
当在 `pom.xml` 或项目中发现了可疑的依赖，或者追踪链路进入了依赖库的包路径（如 `com.company.core.utils`）时，需定位到本地 Maven 仓库或项目 `WEB-INF/lib` 下的 `.jar` 文件。

## 2. ⚠️ 强制工具调用规范 (Auto Decompilation)
**严禁使用普通的 `Read` 工具去直接读取 `.class` 或 `.jar` 文件**，这会导致大量乱码和 Token 浪费。

当遇到需要分析的字节码文件时，你必须调用我们内置的自动反编译脚本：

### 2.1 提取并反编译代码
打开 Terminal 执行以下命令：
```bash
# 场景 1：直接反编译单个 .class 文件
python .trae/skills/shared/scripts/auto_decompile.py /path/to/TargetClass.class

# 场景 2：反编译 .jar 包中隐藏的某个特定类
python .trae/skills/shared/scripts/auto_decompile.py /path/to/library.jar com.company.core.utils.SecretUtil
```
*(注：该脚本在首次运行时会自动下载 CFR 反编译器引擎到本地)*

该脚本会将编译后的 Java 近似源码直接输出到终端，供你继续执行 Source 到 Sink 的流向追踪。

### 2.2 针对 `.jar` 文件的快速全局搜索
如果你不知道目标类在 JAR 包中的具体包名，只想搜索特定的字符串或方法名（如寻找 `readObject`），不要解压整个 JAR 包，直接使用终端管道命令：
```bash
# 在 JAR 包中搜索包含 "readObject" 的类
unzip -l target.jar | grep ".class" | awk '{print $4}' | while read f; do unzip -p target.jar "$f" | strings | grep -q "readObject" && echo "$f contains readObject"; done
```
找到可疑类名后，再将其传入 `auto_decompile.py` 提取源码。

## 3. 字节码还原推断与链路衔接
获取到反编译源码后：
1. 将获取到的代码逻辑，无缝衔接到原本的 Source to Sink 调用链中。
2. 并在报告中注明：“该步骤通过 `auto_decompile.py` 反编译 `xxx-core.jar` 中的 `TargetClass.class` 确认链路连通”。