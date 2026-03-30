# XML 外部实体注入 (XXE) 识别规则库

本文档列出了常见的 Java XML 解析器及其危险与安全的配置特征。

## 1. 危险配置特征 (Vulnerable Patterns)
当以下解析器被实例化，且**未包含**禁用 DTD 或外部实体的配置代码时，即认为存在潜在的高危 XXE 风险。

- `DocumentBuilderFactory.newInstance()`
- `SAXParserFactory.newInstance()`
- `XMLInputFactory.newInstance()`
- `XMLReaderFactory.createXMLReader()`
- 第三方库:
  - `new SAXReader()` (org.dom4j.io.SAXReader)
  - `new SAXBuilder()` (org.jdom2.input.SAXBuilder)
  - `new Digester()` (org.apache.commons.digester3.Digester)

## 2. 安全配置特征 (Safe Patterns)
审计时，应确认实例化后是否紧跟了以下安全配置（Sanitizers）。

### 2.1 JAXP 解析器 (DocumentBuilderFactory / SAXParserFactory)
必须显式设置以下 Feature 之一或全部：
```java
// 禁用 DTD (最安全)
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);

// 禁用外部通用实体和参数实体
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

### 2.2 XMLInputFactory (StAX)
必须禁用外部实体解析：
```java
factory.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, false);
factory.setProperty(XMLInputFactory.SUPPORT_DTD, false); // 推荐一并禁用 DTD
```

### 2.3 dom4j SAXReader
```java
SAXReader reader = new SAXReader();
reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```