# XXE 漏洞 参考资料

本文档收集了关于 XML 外部实体注入 (XXE) 漏洞的防御与规范说明。

## 防御与规范
- [OWASP XXE Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/XML_External_Entity_Prevention_Cheat_Sheet.html)
  OWASP 官方关于防御 XXE 漏洞的速查表，提供了各种 Java 解析器的安全配置代码。
- [Java API for XML Processing (JAXP) Security Guide](https://docs.oracle.com/en/java/javase/17/security/java-api-xml-processing-jaxp-security-guide.html)
  Oracle 官方的 JAXP 安全指南。
- [CWE-611: Improper Restriction of XML External Entity Reference](https://cwe.mitre.org/data/definitions/611.html)
  CWE 关于 XXE 漏洞的官方定义。