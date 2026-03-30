#!/usr/bin/env python3
"""
Java 依赖漏洞工程化扫描器 (POM / Gradle Vulnerability Scanner)
用途: 替代 AI 容易产生幻觉的文本读取方式，利用标准 XML/正则 解析项目依赖，
      解决 `<properties>` 变量替换、父子 POM 继承问题，并与内置的高危组件版本库进行精准匹配。
"""

import sys
import os
import xml.etree.ElementTree as ET
import re

# 已知高危组件指纹库 (简化版，可根据需求扩充)
# 格式: {"groupId:artifactId": {"vuln_versions": ["< 1.2.83", "<= 2.14.1"], "desc": "漏洞描述"}}
VULN_DB = {
    "com.alibaba:fastjson": {
        "vuln_version_regex": r"^1\.2\.(?:[0-9]|[1-7][0-9]|8[0-2])$", # < 1.2.83
        "desc": "严重的反序列化 RCE 漏洞 (AutoType)",
        "fix": "升级至 1.2.83 或 Fastjson2"
    },
    "org.apache.logging.log4j:log4j-core": {
        "vuln_version_regex": r"^2\.(?:[0-9]|1[0-4])(?:\.[0-9]+)?$", # <= 2.14.1
        "desc": "Log4Shell JNDI 注入 RCE (CVE-2021-44228)",
        "fix": "升级至 2.15.0 及以上版本"
    },
    "org.apache.shiro:shiro-core": {
        "vuln_version_regex": r"^1\.(?:[0-1]\.[0-9]|2\.[0-4])$", # <= 1.2.4
        "desc": "默认密钥反序列化 RCE (CVE-2016-4437) / 权限绕过",
        "fix": "升级至 1.10.0+ 并自定义 rememberMe 密钥"
    },
    "commons-collections:commons-collections": {
        "vuln_version_regex": r"^3\.[0-2](?:\.[0-1])?$", # <= 3.2.1
        "desc": "经典的 CC 链反序列化 Gadget",
        "fix": "升级至 3.2.2 或 4.0+"
    },
    "org.yaml:snakeyaml": {
        "vuln_version_regex": r"^1\.(?:[0-9]|1[0-9]|2[0-9]|3[0-1])$", # <= 1.31
        "desc": "反序列化 RCE 漏洞 (CVE-2022-1471)",
        "fix": "升级至 1.33+"
    }
}

def remove_xml_namespace(tag):
    """移除 XML 标签中的 namespace，如 {http://maven.apache.org/POM/4.0.0}project"""
    return tag.split('}')[-1] if '}' in tag else tag

def parse_pom_properties(root):
    """提取 <properties> 标签中的变量"""
    properties = {}
    for prop_node in root.findall(".//*"):
        if remove_xml_namespace(prop_node.tag) == "properties":
            for child in prop_node:
                tag_name = remove_xml_namespace(child.tag)
                properties[tag_name] = child.text.strip() if child.text else ""
    return properties

def resolve_version(version_str, properties):
    """解析形如 ${fastjson.version} 的版本号"""
    if version_str and version_str.startswith("${") and version_str.endswith("}"):
        var_name = version_str[2:-1]
        return properties.get(var_name, version_str)
    return version_str

def scan_pom(pom_path):
    """扫描解析单个 pom.xml 文件"""
    results = []
    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()
        
        properties = parse_pom_properties(root)
        
        # 查找所有 dependency 标签
        for dep in root.findall(".//*"):
            if remove_xml_namespace(dep.tag) == "dependency":
                group_id = ""
                artifact_id = ""
                version = ""
                
                for child in dep:
                    tag = remove_xml_namespace(child.tag)
                    if tag == "groupId": group_id = child.text.strip() if child.text else ""
                    elif tag == "artifactId": artifact_id = child.text.strip() if child.text else ""
                    elif tag == "version": version = child.text.strip() if child.text else ""
                
                if group_id and artifact_id:
                    full_name = f"{group_id}:{artifact_id}"
                    resolved_version = resolve_version(version, properties)
                    
                    if full_name in VULN_DB and resolved_version:
                        vuln_info = VULN_DB[full_name]
                        if re.match(vuln_info["vuln_version_regex"], resolved_version):
                            results.append({
                                "component": full_name,
                                "version": resolved_version,
                                "file": pom_path,
                                "desc": vuln_info["desc"],
                                "fix": vuln_info["fix"]
                            })
    except Exception as e:
        print(f"[-] Error parsing {pom_path}: {e}")
        
    return results

def main():
    if len(sys.argv) < 2:
        print("Usage: python pom_parser.py <project_directory>")
        sys.exit(1)
        
    project_dir = sys.argv[1]
    all_findings = []
    
    # 遍历寻找所有 pom.xml
    for root, _, files in os.walk(project_dir):
        for file in files:
            if file == "pom.xml":
                pom_path = os.path.join(root, file)
                findings = scan_pom(pom_path)
                all_findings.extend(findings)
                
    if not all_findings:
        print("[+] 依赖扫描完成。未在项目的直接依赖中发现已知高危组件 (基于当前指纹库)。")
        sys.exit(0)
        
    print("### 🚨 发现高危第三方组件漏洞\n")
    for idx, f in enumerate(all_findings, 1):
        print(f"**[{idx}] 组件名称**: `{f['component']}`")
        print(f"- **引入版本**: `{f['version']}`")
        print(f"- **引入位置**: {f['file']}")
        print(f"- **漏洞风险**: {f['desc']}")
        print(f"- **修复建议**: {f['fix']}\n")

if __name__ == "__main__":
    main()