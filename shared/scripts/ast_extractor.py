#!/usr/bin/env python3
"""
AST 辅助提取工具 (基于 Tree-sitter)
用途: 在长代码文件中精准提取方法定义、类成员变量和 import 列表，
      以最小的 Token 消耗提供给 AI，避免 LLM 在阅读动辄几千行的 Java 文件时产生幻觉或迷失上下文。
依赖: pip install tree_sitter tree_sitter_java
"""

import sys
import os

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

def extract_imports(root_node, source_code):
    imports = []
    for child in root_node.children:
        if child.type == 'import_declaration':
            imports.append(source_code[child.start_byte:child.end_byte].decode('utf8'))
    return imports

def extract_fields(root_node, source_code):
    fields = []
    # 简单的递归查找 class_declaration -> class_body -> field_declaration
    for child in root_node.children:
        if child.type == 'class_declaration':
            for class_child in child.children:
                if class_child.type == 'class_body':
                    for body_child in class_child.children:
                        if body_child.type == 'field_declaration':
                            fields.append(source_code[body_child.start_byte:body_child.end_byte].decode('utf8'))
    return fields

def extract_method_by_name(root_node, source_code, target_method_name):
    # 使用 AST Query 语法查找特定方法名
    # 这比正则可靠得多，能准确提取完整的方法体
    query_str = """
    (method_declaration
        name: (identifier) @method.name
        (#eq? @method.name "%s")
    ) @method.def
    """ % target_method_name
    
    _, JAVA_LANGUAGE = get_parser()
    query = JAVA_LANGUAGE.query(query_str)
    
    captures = query.captures(root_node)
    
    results = []
    for node, capture_name in captures.items():
        if capture_name == "method.def":
            # 提取整个方法的代码块
            results.append({
                "start_line": node.start_point[0] + 1,
                "end_line": node.end_point[0] + 1,
                "code": source_code[node.start_byte:node.end_byte].decode('utf8')
            })
    return results

def main():
    if len(sys.argv) < 2:
        print("Usage: python ast_extractor.py <file_path> [target_method_name]")
        sys.exit(1)
        
    file_path = sys.argv[1]
    target_method = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not os.path.exists(file_path):
        print(f"Error: File not found - {file_path}")
        sys.exit(1)
        
    with open(file_path, 'rb') as f:
        source_code = f.read()
        
    parser, _ = get_parser()
    tree = parser.parse(source_code)
    root_node = tree.root_node
    
    print(f"=== File: {file_path} ===\n")
    
    print("--- [1] Imports ---")
    imports = extract_imports(root_node, source_code)
    for imp in imports:
        print(imp)
    print("\n")
    
    print("--- [2] Class Fields (Variables) ---")
    fields = extract_fields(root_node, source_code)
    for field in fields:
        print(field)
    print("\n")
    
    if target_method:
        print(f"--- [3] Method Extraction: {target_method} ---")
        methods = extract_method_by_name(root_node, source_code, target_method)
        if not methods:
            print(f"Method '{target_method}' not found.")
        for m in methods:
            print(f"// Lines: {m['start_line']} - {m['end_line']}")
            print(m['code'])
            print("-" * 40)

if __name__ == "__main__":
    main()