# 数据流分析 参考资料

本文档收集了用于理解污点分析和调用链追踪的理论与工具资源。

## 分析理论与工具
- [OWASP Code Review Guide](https://owasp.org/www-project-code-review-guide/)
  OWASP 官方的代码审查指南，包含了如何系统性地追踪数据流。
- [Taint Analysis in Static Application Security Testing (SAST)](https://en.wikipedia.org/wiki/Taint_checking)
  关于污点分析（Taint Analysis）基本概念的维基百科条目。
- [Find-Sec-Bugs (Java static analysis tool)](https://find-sec-bugs.github.io/)
  著名的 Java 安全静态分析工具，其内部也使用了类似的数据流追踪机制来发现漏洞。