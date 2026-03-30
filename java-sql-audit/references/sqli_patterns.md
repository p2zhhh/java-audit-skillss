# SQL 注入特征识别规则库

本文档列出了在不同 Java ORM 及数据库访问框架中，可能导致 SQL 注入的高危特征。

## 1. MyBatis
MyBatis 是国内最常用的 ORM 框架，其注入漏洞几乎全部源于 `${}` 的滥用。
- **高危特征 (`$` 拼接)**:
  - `ORDER BY ${columnName}`: 最常见的注入点，因为 `ORDER BY` 后面不能使用 `#` 进行预编译。
  - `LIKE '%${keyword}%'`: 正确的做法应是 `LIKE concat('%', #{keyword}, '%')`。
  - `IN (${ids})`: 集合操作，正确做法应使用 `<foreach>` 标签结合 `#`。
  - 表名动态拼接: `SELECT * FROM ${tableName}`。

## 2. Hibernate / JPA
Hibernate 默认支持 HQL (Hibernate Query Language)，如果使用不当也会产生注入。
- **高危特征 (字符串拼接)**:
  - 动态拼接 HQL: `session.createQuery("FROM User WHERE name = '" + name + "'")`
  - 动态拼接 Native SQL: `session.createNativeQuery("SELECT * FROM user WHERE id = " + id)`
- **安全特征**: 必须使用 `.setParameter()` 方法。

## 3. 纯 JDBC
最基础的数据库访问方式。
- **高危特征**:
  - `Statement.executeQuery("SELECT * FROM users WHERE name = '" + name + "'")`
  - 即使使用了 `PreparedStatement`，如果在传入前 SQL 语句本身已被拼接改变，同样存在漏洞：
    ```java
    String sql = "SELECT * FROM " + tableName + " WHERE id = ?";
    PreparedStatement ps = conn.prepareStatement(sql);
    ```

## 4. Spring Data JDBC / JdbcTemplate
- **高危特征**:
  - `jdbcTemplate.queryForList("SELECT * FROM users WHERE name = '" + name + "'")`
  - 使用 `+` 号或 `String.format()` 构建 SQL 语句。