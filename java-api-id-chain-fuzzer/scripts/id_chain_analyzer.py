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
    """
    判断接口是否属于危险的写/删操作。
    注意：这只是基于关键字的初步打标（Warning Flagger）。
    最终是否剔除该接口，由 Agent 通过阅读源码进行语义级安全校验（Semantic Safety Check）决定。
    """
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
    
    sources = []  # 潜在的泄漏源 (GET/List 接口)
    sinks = []    # 潜在的利用点 (需要特定参数的接口)
    
    print("[*] Filtering and analyzing endpoints for Parameter Chaining...")
    
    for route in routes:
        path = route.get("path", "")
        handler = route.get("handler", "")
        http_method = route.get("http_method", "GET")
        parameters = route.get("parameters", [])
        
        # 记录脚本的危险打标，但不直接剔除，留给 Agent 裁决
        is_dangerous = is_dangerous_endpoint(path, handler)
        
        # 分析参数：不再局限于 ID，提取所有该接口需要的必填/关键参数名
        required_params = [param.get("name", "") for param in parameters if param.get("name", "")]
                
        # 启发式分类
        # 如果是一个 GET 接口，且名字里有 list/query/page/detail，很可能是个 Source（能查出实体数据）
        is_source_api = any(kw in handler.lower() or kw in path.lower() for kw in ['list', 'query', 'page', 'search', 'all', 'detail', 'info'])
        
        if is_source_api and http_method in ['GET', 'POST']:
            sources.append({
                "path": path,
                "method": http_method,
                "handler": handler,
                "script_warning_dangerous": is_dangerous,
                "likely_leaks": "Entity parameters (IDs, tokens, hashes, etc.)"
            })
            
        # 如果接口明确要求传入参数，它就是一个 Sink（靶点）
        if required_params:
            sinks.append({
                "path": path,
                "method": http_method,
                "handler": handler,
                "script_warning_dangerous": is_dangerous,
                "required_params": required_params,
                "is_composite_key": len(required_params) > 1
            })
            
    # 构建串联图谱
    chain_graph = {
        "metadata": {
            "total_safe_sources": len(sources),
            "total_exploitable_sinks": len(sinks)
        },
        "sources_for_leakage": sources,
        "sinks_for_exploitation": sinks,
        "fuzzing_strategy": "1. Extract ALL bound parameters (e.g., userid, token, order_no) from 'sources_for_leakage' JSON arrays.\n2. Inject bound parameter sets into 'sinks_for_exploitation' maintaining their relational integrity.\n3. Observe HTTP responses for IDOR or Information Disclosure."
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
