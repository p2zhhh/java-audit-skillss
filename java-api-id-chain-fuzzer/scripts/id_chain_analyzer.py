import os
import json
import argparse
import re
from typing import List, Dict, Set

# 黑名单关键字，包含这些词的接口将被视为“破坏性操作”，不参与 Fuzzing
DANGEROUS_KEYWORDS = {
    'delete', 'del', 'remove', 'update', 'modify', 
    'edit', 'reset', 'clear', 'drop', 'insert', 'add', 'create'
}

def is_dangerous_endpoint(path: str, method_name: str) -> bool:
    """判断接口是否属于危险的写/删操作"""
    target = (path + " " + method_name).lower()
    for kw in DANGEROUS_KEYWORDS:
        if kw in target:
            return True
    return False

def analyze_id_chain(routes_json_path: str, output_path: str):
    """
    读取 route-mapper 提取的路由表，构建 ID 泄漏与利用的关系图。
    """
    if not os.path.exists(routes_json_path):
        print(f"[-] Error: Routes file {routes_json_path} not found.")
        return

    with open(routes_json_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        
    routes = data.get("routes", [])
    
    # 我们关注的 ID 字段名，必须忽略大小写，匹配以 id, ID, Id 结尾的字段
    # 例如: userid, userID, userId, doc_id, openid
    id_patterns = re.compile(r'([a-zA-Z0-9_]*id)$', re.IGNORECASE)
    
    sources = []  # 潜在的泄漏源 (GET/List 接口)
    sinks = []    # 潜在的利用点 (需要 ID 的接口)
    
    print("[*] Filtering and analyzing endpoints for ID Chaining...")
    
    for route in routes:
        path = route.get("path", "")
        handler = route.get("handler", "")
        http_method = route.get("http_method", "GET")
        parameters = route.get("parameters", [])
        
        # 剔除危险操作
        if is_dangerous_endpoint(path, handler):
            continue
            
        # 分析参数中是否需要 ID
        needs_id = False
        required_ids = []
        for param in parameters:
            p_name = param.get("name", "")
            if id_patterns.search(p_name):
                needs_id = True
                required_ids.append(p_name)
                
        # 启发式分类
        # 如果是一个 GET 接口，且名字里有 list/query/page，很可能是个 Source（能查出一批数据，泄露 ID）
        is_list_api = any(kw in handler.lower() or kw in path.lower() for kw in ['list', 'query', 'page', 'search', 'all'])
        
        if is_list_api and http_method in ['GET', 'POST']:
            sources.append({
                "path": path,
                "method": http_method,
                "handler": handler,
                "likely_leaks": "IDs associated with the query"
            })
            
        # 如果接口明确要求传入 ID，它就是一个 Sink（靶点）
        # 特别注意：有些接口需要多个 ID（如 userid 和 openid），需要将它们作为一组复合主键处理
        if needs_id:
            sinks.append({
                "path": path,
                "method": http_method,
                "handler": handler,
                "required_ids": required_ids,
                "is_composite_key": len(required_ids) > 1
            })
            
    # 构建串联图谱
    chain_graph = {
        "metadata": {
            "total_safe_sources": len(sources),
            "total_exploitable_sinks": len(sinks)
        },
        "sources_for_leakage": sources,
        "sinks_for_exploitation": sinks,
        "fuzzing_strategy": "1. Extract bound ID pairs (e.g., userid & openid) from 'sources_for_leakage' JSON arrays.\n2. Inject bound IDs into 'sinks_for_exploitation' maintaining their relational integrity.\n3. Observe HTTP responses for IDOR or Information Disclosure."
    }
    
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(chain_graph, f, indent=4)
        
    print(f"[+] ID Chain graph generated successfully: {output_path}")
    print(f"    - Found {len(sources)} potential ID leakage sources.")
    print(f"    - Found {len(sinks)} potential ID exploitation sinks.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API ID Chain Fuzzer Pre-processor")
    parser.add_argument("-i", "--input", required=True, help="Input routes.json from java-route-mapper")
    parser.add_argument("-o", "--output", required=True, help="Output chain_graph.json")
    args = parser.parse_args()
    
    analyze_id_chain(args.input, args.output)
