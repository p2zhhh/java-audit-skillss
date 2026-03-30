# Java SQL 注入审查 参考资料

本文档收集了用于理解和防御 Java 持久层中 SQL 注入漏洞的相关指南。

## 注入防御指南
- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
  OWASP 提供的全面防御 SQL 注入的速查表，强调了参数化查询的重要性。

## 框架特定文档
- [MyBatis Documentation - String Substitution](https://mybatis.org/mybatis-3/sqlmap-xml.html#String_Substitution)
  MyBatis 官方文档关于 `${}` 字符串替换机制的说明及其安全风险提示。
- [Hibernate ORM Documentation - Queries](https://docs.jboss.org/hibernate/orm/current/userguide/html_single/Hibernate_User_Guide.html#query)
  Hibernate 官方用户指南，介绍了如何安全地构建 HQL 和 Native SQL 查询。