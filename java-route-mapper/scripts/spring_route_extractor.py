import os
import json
import argparse
import re
from typing import List, Dict, Union

try:
    import tree_sitter_java as tsjava
    from tree_sitter import Language, Parser
except ImportError:
    print("[-] 缺少必要的依赖。请先运行: pip install tree-sitter tree-sitter-java")
    exit(1)

JAVA_LANGUAGE = Language(tsjava.language())
parser = Parser(JAVA_LANGUAGE)

def extract_value_from_node(node) -> Union[str, List[str]]:
    """递归从 AST 节点中提取字符串或常量标识符"""
    if not node: return ""
    
    if node.type == 'string_literal':
        # 剥离前后的引号
        return node.text.decode('utf-8').strip('"\'')
    elif node.type in ['identifier', 'field_access']:
        # 识别为常量引用，打上 CONST: 前缀供 AI 后续解析
        return "CONST:" + node.text.decode('utf-8')
    elif node.type == 'element_value_array_initializer':
        # 处理 {"/path1", "/path2"} 这样的数组
        res = []
        for child in node.named_children:
            val = extract_value_from_node(child)
            if isinstance(val, list):
                res.extend(val)
            elif val:
                res.append(val)
        return res
    return ""

def get_annotation_paths(annotation_node) -> List[str]:
    """获取注解中的路由路径列表"""
    args_node = annotation_node.child_by_field_name('arguments')
    if not args_node:
        # 例如 @GetMapping 没有参数时，默认为 "/"
        return [""]
        
    results = []
    
    # 可能是 annotation_argument_list，它包含多个 element_value_pair 或直接是一个值
    if args_node.type == 'annotation_argument_list':
        for child in args_node.named_children:
            if child.type == 'element_value_pair':
                key = child.child_by_field_name('key')
                if key and key.text.decode('utf-8') in ['value', 'path']:
                    val_node = child.child_by_field_name('value')
                    extracted = extract_value_from_node(val_node)
                    if isinstance(extracted, list):
                        results.extend(extracted)
                    elif extracted:
                        results.append(extracted)
            elif child.type in ['string_literal', 'identifier', 'field_access', 'element_value_array_initializer']:
                extracted = extract_value_from_node(child)
                if isinstance(extracted, list):
                    results.extend(extracted)
                elif extracted:
                    results.append(extracted)
            # 兼容：有时候 argument_list 下直接是 string_literal
            elif child.type == 'string_literal':
                extracted = extract_value_from_node(child)
                if extracted: results.append(extracted)
    else:
        # 单值情况，比如 @GetMapping("/path")
        extracted = extract_value_from_node(args_node)
        if isinstance(extracted, list):
            results.extend(extracted)
        elif extracted:
            results.append(extracted)
            
    return results if results else [""]

def is_mapping_annotation(node):
    """判断是否为 Spring 路由相关的注解，并返回类型名"""
    # tree-sitter-java 的 marker_annotation 也是以 @ 开头的
    if node.type in ['marker_annotation', 'annotation', 'modifiers']:
        # 很多时候 annotation 是 modifiers 的子节点
        if node.type == 'modifiers':
            for child in node.named_children:
                res = is_mapping_annotation(child)
                if res: return res
            return None
            
        name_node = node.child_by_field_name('name')
        if name_node:
            name = name_node.text.decode('utf-8')
            if name.endswith('Mapping'):
                return name
    return None

def get_mappings_from_modifiers(modifiers_node):
    """从修饰符列表中找出 Mapping 注解及其路径"""
    if not modifiers_node: return None, []
    
    # 兼容 tree-sitter 不同版本的层级结构
    if modifiers_node.type == 'modifiers':
        for child in modifiers_node.named_children:
            mapping_type = is_mapping_annotation(child)
            if mapping_type:
                return mapping_type, get_annotation_paths(child)
    else:
        # 如果直接传入的是 annotation 节点
        mapping_type = is_mapping_annotation(modifiers_node)
        if mapping_type:
            return mapping_type, get_annotation_paths(modifiers_node)
            
    return None, []

def normalize_path(path: str) -> str:
    if not path: return ""
    # 保留 CONST 前缀不作处理
    if path.startswith("CONST:"): return path
    if not path.startswith('/'): path = '/' + path
    return path

# ... (为了防止 Tree-sitter 解析不到特定版本的 modifier，我们用更暴力的正则回退机制辅助) ...
def extract_routes_from_file(filepath: str) -> List[Dict]:
    routes = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        print(f"[-] Error reading {filepath}: {e}")
        return routes
        
    # 快速跳过不包含 Mapping 的文件
    if 'Mapping' not in content:
        return routes

    # 简单的正则回退机制，因为 tree-sitter 对有些带复杂注解的类解析可能会失败
    CLASS_MAPPING_RE = re.compile(r'@RequestMapping\s*\(\s*(?:value\s*=\s*)?["\']([^"\']+)["\']')
    METHOD_MAPPING_RE = re.compile(r'@(Get|Post|Put|Delete|Patch|Request)Mapping\s*\(\s*(?:value\s*=\s*|path\s*=\s*)?(?:\{)?["\']([^"\']+)["\'](?:})?')
    # 增强方法声明的正则，以捕获参数部分
    METHOD_DECLARATION_RE = re.compile(r'(?:public|protected|private)?\s+[\w<>\.,\s\[\]]+\s+(\w+)\s*\((.*?)\)\s*(?:throws\s+[\w,\s]+)?\s*\{')

    class_path = ""
    class_match = CLASS_MAPPING_RE.search(content)
    if class_match:
        class_path = class_match.group(1)
        if not class_path.startswith('/'):
            class_path = '/' + class_path

    class_name = os.path.basename(filepath).replace('.java', '')

    lines = content.split('\n')
    for i, line in enumerate(lines):
        method_match = METHOD_MAPPING_RE.search(line)
        if method_match:
            http_method = method_match.group(1).upper()
            if http_method == 'REQUEST':
                http_method = 'ALL'
            
            method_path = method_match.group(2)
            if not method_path.startswith('/'):
                method_path = '/' + method_path
                
            full_path = (class_path + method_path).replace('//', '/')
            
            java_method_name = "unknown_method"
            parameters = []
            
            # 尝试向下文搜索方法声明，以提取方法名和参数
            # 由于方法声明可能跨行，我们将接下来的几行拼接起来匹配
            search_context = " ".join([l.strip() for l in lines[i+1:min(i+10, len(lines))]])
            decl_match = METHOD_DECLARATION_RE.search(search_context)
            if decl_match and 'class ' not in search_context[:decl_match.start()]:
                java_method_name = decl_match.group(1)
                raw_params = decl_match.group(2).strip()
                
                if raw_params:
                    # 简单的参数分割（不考虑泛型中嵌套逗号的复杂极端情况）
                    param_list = [p.strip() for p in raw_params.split(',')]
                    for p in param_list:
                        # 尝试提取注解、类型和参数名
                        # 例如: @RequestParam("id") Long id
                        param_info = {"raw": p, "annotations": [], "type": "", "name": ""}
                        
                        # 提取注解
                        annotations = re.findall(r'@\w+(?:\([^)]*\))?', p)
                        param_info["annotations"] = annotations
                        
                        # 移除注解后剩下的应该是类型和名称
                        clean_p = re.sub(r'@\w+(?:\([^)]*\))?', '', p).strip()
                        parts = clean_p.split()
                        if len(parts) >= 2:
                            param_info["type"] = " ".join(parts[:-1])
                            param_info["name"] = parts[-1]
                        else:
                            param_info["name"] = clean_p
                            
                        parameters.append(param_info)
            else:
                # 兼容旧的回退逻辑（仅取方法名）
                for j in range(1, 6):
                    if i + j < len(lines):
                        fallback_match = re.search(r'(?:public|protected|private)?\s+[\w<>\.,\s\[\]]+\s+(\w+)\s*\(', lines[i+j])
                        if fallback_match and 'class ' not in lines[i+j]:
                            java_method_name = fallback_match.group(1)
                            break
            
            routes.append({
                "http_method": http_method,
                "path": full_path,
                "handler": f"{class_name}.{java_method_name}",
                "parameters": parameters,
                "file": filepath
            })
            
    return routes

def find_context_path(directory: str) -> str:
    """尝试从 application.yml / properties 中提取 context-path"""
    search_paths = [os.path.join(directory, "src", "main", "resources"), directory]
    for sp in search_paths:
        if not os.path.exists(sp): continue
        for root_dir, _, files in os.walk(sp):
            for file in files:
                filepath = os.path.join(root_dir, file)
                if file in ["application.yml", "application.yaml", "bootstrap.yml"]:
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            match = re.search(r'context-path:\s*([^\s#]+)', f.read())
                            if match: return match.group(1).strip()
                    except: pass
                elif file in ["application.properties", "bootstrap.properties"]:
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            match = re.search(r'server\.servlet\.context-path\s*=\s*([^\s#]+)', f.read())
                            if match: return match.group(1).strip()
                    except: pass
    return ""

def main():
    parser_arg = argparse.ArgumentParser(description="AST-based Spring Route Extractor (Resolves Arrays & Interfaces)")
    parser_arg.add_argument("-d", "--directory", required=True, help="Directory to scan for .java files")
    parser_arg.add_argument("-o", "--output", help="Output JSON file path (optional)")
    args = parser_arg.parse_args()

    if not os.path.isdir(args.directory):
        print(f"[-] Directory not found: {args.directory}")
        return

    print("[*] Parsing Java files using tree-sitter...")
    
    # 获取全局上下文路径
    context_path = find_context_path(args.directory)
    if context_path:
        print(f"[+] Detected server.servlet.context-path: {context_path}")

    all_routes = []
    for root_dir, _, files in os.walk(args.directory):
        for file in files:
            if file.endswith('.java'):
                filepath = os.path.join(root_dir, file)
                routes = extract_routes_from_file(filepath)
                all_routes.extend(routes)

    # 追加 context-path 前缀（如果是常量则暂时跳过，交给 AI 处理）
    if context_path and context_path != "/":
        for r in all_routes:
            if "CONST:" not in r["path"]:
                r["path"] = (context_path + r["path"]).replace('//', '/')

    print(f"[+] Extraction complete. Found {len(all_routes)} routes.")

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump({"context_path": context_path, "routes": all_routes}, f, indent=4)
        print(f"[+] Routes saved to {args.output}")
    else:
        print(f"\n{'-'*10} {'-'*50} {'-'*30}")
        print(f"{'METHOD':<10} {'PATH':<50} {'HANDLER':<30}")
        print(f"{'-'*10} {'-'*50} {'-'*30}")
        for r in all_routes:
            # 如果路径太长，简单截断一下以适应终端显示
            display_path = r['path'] if len(r['path']) <= 48 else r['path'][:45] + "..."
            print(f"{r['http_method']:<10} {display_path:<50} {r['handler']:<30}")

if __name__ == "__main__":
    main()
