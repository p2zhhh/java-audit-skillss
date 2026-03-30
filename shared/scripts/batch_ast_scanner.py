#!/usr/bin/env python3
"""
AST 批量安全扫描预处理工具 (基于 Tree-sitter)
用途: 在审计初期主动对整个 Java 项目目录进行快速扫描。
功能:
  1. 找出所有包含 @Controller, @RestController 的文件及其路由注解。
  2. 提取出所有潜在的高危方法调用 (如 readObject, exec, new File, parseObject)。
  3. 生成一个紧凑的 JSON 或 Markdown 清单，供大模型做下一步深度追踪的地图。
"""

import sys
import os
import json

try:
    from tree_sitter import Language, Parser
    import tree_sitter_java
except ImportError:
    print("Error: Missing tree-sitter dependencies.")
    print("Please install via: pip install tree_sitter tree_sitter_java")
    sys.exit(1)

def get_parser():
    JAVA_LANGUAGE = Language(tree_sitter_java.language())
    parser = Parser(JAVA_LANGUAGE)
    return parser, JAVA_LANGUAGE

def scan_file(file_path, parser, java_lang):
    with open(file_path, 'rb') as f:
        source_code = f.read()
        
    tree = parser.parse(source_code)
    root_node = tree.root_node
    
    results = {
        "file": file_path,
        "is_controller": False,
        "endpoints": [],
        "sinks": []
    }
    
    # 1. 查找是否是 Controller
    controller_query = java_lang.query("""
    (class_declaration
        (modifiers
            (marker_annotation name: (identifier) @annotation
            (#match? @annotation "RestController|Controller")
            )
        )
    )
    """)
    if controller_query.captures(root_node):
        results["is_controller"] = True
        
        # 提取方法上的 RequestMapping/GetMapping 等
        mapping_query = java_lang.query("""
        (method_declaration
            (modifiers
                (marker_annotation name: (identifier) @mapping
                (#match? @mapping ".*Mapping")
                )
            )
            name: (identifier) @method_name
        )
        """)
        for node, capture_name in mapping_query.captures(root_node).items():
            if capture_name == "method_name":
                results["endpoints"].append({
                    "method": source_code[node.start_byte:node.end_byte].decode('utf8'),
                    "line": node.start_point[0] + 1
                })

    # 2. 查找高危 Sink 调用
    # 这里用正则匹配一些常见的高危函数名
    sink_query = java_lang.query("""
    (method_invocation
        name: (identifier) @method_call
        (#match? @method_call "^(readObject|exec|parseObject|readValue|getCanonicalPath|executeQuery|queryForList)$")
    ) @invocation
    """)
    
    for node, capture_name in sink_query.captures(root_node).items():
        if capture_name == "method_call":
            results["sinks"].append({
                "sink_type": source_code[node.start_byte:node.end_byte].decode('utf8'),
                "line": node.start_point[0] + 1
            })
            
    # 查找 Object Creation (如 new File)
    obj_query = java_lang.query("""
    (object_creation_expression
        type: (type_identifier) @class_name
        (#match? @class_name "^(File|FileInputStream|SAXReader)$")
    )
    """)
    for node, capture_name in obj_query.captures(root_node).items():
        results["sinks"].append({
            "sink_type": "new " + source_code[node.start_byte:node.end_byte].decode('utf8'),
            "line": node.start_point[0] + 1
        })

    return results if (results["is_controller"] or results["sinks"]) else None

def main():
    if len(sys.argv) < 2:
        print("Usage: python batch_ast_scanner.py <project_directory>")
        sys.exit(1)
        
    project_dir = sys.argv[1]
    if not os.path.isdir(project_dir):
        print(f"Error: Directory not found - {project_dir}")
        sys.exit(1)
        
    parser, java_lang = get_parser()
    
    findings = []
    
    # 遍历目录下所有 Java 文件
    for root, _, files in os.walk(project_dir):
        for file in files:
            if file.endswith('.java'):
                file_path = os.path.join(root, file)
                try:
                    res = scan_file(file_path, parser, java_lang)
                    if res:
                        findings.append(res)
                except Exception as e:
                    # 忽略解析错误的个别文件
                    continue
                    
    # 输出 Markdown 报告供大模型阅读
    print("# AST 预扫描报告 (AST Pre-scan Report)\n")
    
    print("## 🗺️ Controllers & Endpoints")
    for f in findings:
        if f["is_controller"]:
            print(f"- **{f['file']}**")
            for ep in f["endpoints"]:
                print(f"  - Method: `{ep['method']}` (Line: {ep['line']})")
                
    print("\n## ☢️ 潜在高危 Sink (Potential Sinks)")
    for f in findings:
        if f["sinks"]:
            print(f"- **{f['file']}**")
            for s in f["sinks"]:
                print(f"  - Sink: `{s['sink_type']}` (Line: {s['line']})")

if __name__ == "__main__":
    main()