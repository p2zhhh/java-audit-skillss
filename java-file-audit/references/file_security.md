# Java 文件操作漏洞 参考资料

本文档收集了关于路径穿越和文件上传漏洞的防御指南。

## 漏洞防御与规范
- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
  OWASP 关于如何安全处理文件上传的速查表。
- [OWASP Path Traversal](https://owasp.org/www-community/attacks/Path_Traversal)
  关于路径穿越漏洞的详细介绍和防御建议。
- [CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')](https://cwe.mitre.org/data/definitions/22.html)
  CWE 关于路径穿越漏洞的官方定义。
- [CWE-434: Unrestricted Upload of File with Dangerous Type](https://cwe.mitre.org/data/definitions/434.html)
  CWE 关于危险文件上传漏洞的官方定义。