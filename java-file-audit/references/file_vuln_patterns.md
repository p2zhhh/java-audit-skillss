# 文件操作漏洞识别规则库

本文档列出了在 Java 中可能导致任意文件读取、下载、上传或路径穿越的代码特征。

## 1. 路径穿越与任意文件读取/下载
### 1.1 高危 Sink
- `new java.io.File(basePath, userInput)` 或 `new File(userInput)`
- `java.nio.file.Paths.get(userInput)`
- `new java.io.FileInputStream(file)`
- `org.springframework.util.FileCopyUtils.copy(...)`
- `org.apache.commons.io.FileUtils.readFileToByteArray(...)`

### 1.2 危险特征 (缺乏规范化)
- 直接将外部传入的 `fileName` 与基础路径进行字符串拼接：`String filePath = BASE_DIR + "/" + fileName;`
- **未验证**拼接后的路径是否越界（如使用了 `../`）。

### 1.3 安全特征 (Sanitizer)
- 使用 `File.getCanonicalPath()` 获取绝对路径，并检查是否以允许的基础目录开头：
  ```java
  File file = new File(BASE_DIR, userInput);
  if (!file.getCanonicalPath().startsWith(new File(BASE_DIR).getCanonicalPath())) {
      throw new SecurityException("Invalid path");
  }
  ```
- 严格过滤了穿越序列：`fileName.replace("../", "")` (注意：需评估此过滤是否可被双写如 `..././` 绕过)。

## 2. 任意文件上传漏洞
### 2.1 上传入口特征
- Spring: `@RequestParam("file") MultipartFile file`
- Servlet: `request.getPart("file")`
- Commons FileUpload: `ServletFileUpload.parseRequest(request)`

### 2.2 高危特征
- **信任用户输入的文件名**: 直接使用 `file.getOriginalFilename()` 作为保存的文件名。
- **缺乏白名单校验**: 仅使用了黑名单（如 `.jsp`），可能被 `.jspx`, `.Jsp` 等绕过。
- **路径穿越上传**: 上传保存的路径拼接了 `getOriginalFilename()`，若文件名包含 `../`，可能导致文件上传到 `/etc/cron.d` 或 `WEB-INF`。

### 2.3 安全特征
- 保存时使用随机生成的 UUID 重命名文件。
- 使用严格的后缀名白名单机制。
- 将文件保存在专门的 OSS 对象存储或 Web 根目录之外的隔离目录。