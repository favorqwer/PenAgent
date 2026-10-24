# 多机器协同控制与网络拓扑说明 (agents.md)

本文档说明在本项目架构中，**Windows 物理机 A（控制端）**、**Kali Linux（攻击机）** 与 **Ubuntu（测试靶机）** 之间的网络拓扑、控制机制以及操作方式。

---

## 一、网络拓扑与节点清单

三台主机通过 Tailscale Mesh 专网实现点对点双向互通，拓扑结构如下：

```text
┌────────────────────────────────────────────────────────────────────────┐
│                      Windows 物理机 A (控制机)                          │
│                      Tailscale IP: 100.64.216.52                       │
│                      公钥: ssh-ed25519 AAAAC3NzaC1l... (免密主控)       │
│                                                                        │
│  ┌──────────────────────────────────────────────────────────────────┐  │
│  │  PenAgent 核心控制器                                              │  │
│  │  ├─ 协同 Agent (Collector / Scanner / Exploiter)                 │  │
│  │  ├─ 大模型大脑 (LLM API: OpenAI / DeepSeek 等)                    │  │
│  │  └─ Session 状态存储 (MySQL)                                     │  │
│  └──────────────────┬─────────────────────────────┬─────────────────┘  │
└─────────────────────┼─────────────────────────────┼────────────────────┘
                      │ 控制链路 A                   │ 管理链路 B
                      │ (SSH: 派发渗透命令)          │ (SSH: 运维/环境准备)
                      ▼                             ▼
┌────────────────────────────────────────┐  ┌────────────────────────────┐
│      Kali Linux (攻击机)               │  │   Ubuntu (测试靶机)        │
│      Tailscale IP: 100.74.213.15       │  │   Tailscale IP: 100.84.151.2 │
│      账号: kali / kali                 │  │   账号: ubuntu / wsad      │
│      角色: 运行 nmap/gobuster/msf 等   │  │   角色: 漏洞环境与攻击目标 │
└──────────────────┬─────────────────────┘  └─────────────▲──────────────┘
                   │                                      │
                   └──────────────── 攻击链路 ────────────┘
                         (Tailscale IP 互通, RTT ~58ms)
```

### 节点参数汇总表

| 节点类型 | 主机名 | Tailscale IP | 登录账号 / 密码 | 认证方式 | sudo 提权 | 角色定位 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **控制端** | `desktop-kr5e6e8` | `100.64.216.52` | Windows 本机 | 本地运行环境 | - | 运行 Agent 决策框架 |
| **攻击机** | `kali` | `100.74.213.15` | `kali` / `kali` | Ed25519 公钥免密 | 密码 `kali` 提权至 root | 执行实际扫描与渗透命令 |
| **靶机** | `ubuntu-virtual-machine-1` | `100.84.151.2` | `ubuntu` / `wsad` | Ed25519 公钥免密 | 密码 `wsad` 提权至 root | 承载被测靶场服务 |

---

### 连接配置切换（lab1 / lab2）

两套实验环境通过 `--kali` + `-t` 切换，端口与账号密码沿用 `config/yaml/basic_config.yaml`：

| 配置 | Kali | 靶机 | 命令 |
| :--- | :--- | :--- | :--- |
| **lab1** | `100.74.213.15` | `100.84.151.2` | `run_lab1.cmd` 或 `python cli.py agent --kali 100.74.213.15 -t 100.84.151.2` |
| **lab2** | `100.116.135.31` | `100.86.108.4` | `run_lab2.cmd` 或 `python cli.py agent --kali 100.116.135.31 -t 100.86.108.4` |

说明：

- `--kali` 只覆盖 Kali 主机地址，SSH 端口、用户名、密码仍来自 `basic_config.yaml`。
- 切换时会关闭已打开的 SSH 连接，下一条命令自动连到新 Kali。
- 默认 thread id 形如 `agent-<target>-<随机串>`；用 `--resume` 恢复时若 checkpoint 里的目标与 `-t` 不一致会直接报错，避免串环境。
- 旧命令 `penagent` 也支持 `--kali`。

## 二、Windows 如何控制 Kali（攻击机）

Windows 对 Kali 的控制分为 **PenAgent 自动化调度控制** 和 **人工终端直接控制** 两种途径：

### 1. PenAgent 框架自动控制

项目配置文件 [`config/yaml/basic_config.yaml`](file:///C:/Users/Favor/Desktop/PenAgent/config/yaml/basic_config.yaml) 中已写入 Kali 节点配置：

```yaml
kali:
  hostname: 100.74.213.15
  port: 22
  username: kali
  password: kali
```

#### 调用流程
1. PenAgent 启动时，[`ShellManager`](file:///C:/Users/Favor/Desktop/PenAgent/actions/shell_manager.py#L7-L52) 通过 Paramiko 建立连接，生成 [`RemoteShell`](file:///C:/Users/Favor/Desktop/PenAgent/actions/remote_shell.py#L78-L157) 单例实例。
2. 多 Agent 角色（如 [`Collector`](file:///C:/Users/Favor/Desktop/PenAgent/roles/collector.py) 信息收集、[`Scanner`](file:///C:/Users/Favor/Desktop/PenAgent/roles/scanner.py) 漏洞扫描、[`Exploiter`](file:///C:/Users/Favor/Desktop/PenAgent/roles/exploiter.py) 漏洞利用）根据 LLM 规划出命令。
3. [`ExecuteTask`](file:///C:/Users/Favor/Desktop/PenAgent/actions/execute_task.py#L21-L62) 调用 `shell.execute_cmd(command)`。
4. 命令在 Kali 的 Shell 中执行，执行过程中的终端回显由 `SSHOutputHandler` 捕获并清洗，返回给控制端的 LLM 进行后续推理。

### 2. Windows 命令行直接运维 Kali

在 Windows PowerShell 或 CMD 中：

* **交互式登录**（已配置密钥，直接免密进入）：
  ```powershell
  ssh kali@100.74.213.15
  ```
* **执行单条无交互命令**：
  ```powershell
  ssh kali@100.74.213.15 "whoami; uptime; ip -br a"
  ```
* **需要 root 权限的提权命令**（通过标准输入注入密码）：
  ```powershell
  ssh kali@100.74.213.15 "echo 'kali' | sudo -S systemctl status ssh"
  ```

---

## 三、Windows 如何控制 Ubuntu（靶机）

Ubuntu 作为目标测试靶机，Windows 控制机主要负责准备测试环境、查看靶机运行状态、排查测试日志以及还原快照或重置靶场服务。

### Windows 命令行直接控制 Ubuntu

* **交互式登录**（已配置密钥，免密登录）：
  ```powershell
  ssh ubuntu@100.84.151.2
  ```
* **执行单条无交互命令**：
  ```powershell
  ssh ubuntu@100.84.151.2 "uname -a; ss -tuln"
  ```
* **需要 root 权限的提权命令**（通过密码 `wsad` 提权）：
  ```powershell
  ssh ubuntu@100.84.151.2 "echo 'wsad' | sudo -S systemctl status mysql"
  ```
* **文件传输（往靶机部署靶场环境）**：
  ```powershell
  scp .\target_app.zip ubuntu@100.84.151.2:/home/ubuntu/
  ```

---

## 四、攻击链路与实际运作流程

当在 Windows 控制端运行 PenAgent（例如执行 `python cli.py penagent -m 5`）时，数据与控制指令流转如下：

```text
[Windows 控制端: PenAgent]
         │ 1. 提问任务: "对 100.84.151.2 进行信息收集与渗透测试"
         ▼
[LLM 智能推理决策]
         │ 2. 规划任务: 生成指令 (例如: nmap -sV -p- 100.84.151.2)
         ▼
[actions/shell_manager.py]
         │ 3. Paramiko SSH 管道将指令发送至 100.74.213.15
         ▼
[Kali Linux 攻击机]
         │ 4. 执行 nmap 工具，向目标 100.84.151.2 发送探测流量
         ▼
[Ubuntu 测试靶机 (100.84.151.2)]
         │ 5. 端口响应流量
         ▼
[Kali Linux 攻击机]
         │ 6. 捕获 nmap 输出结果
         ▼
[Windows 控制端: PenAgent]
         │ 7. 接收输出 -> 存入 MySQL -> 交由下一轮 Agent (Scanner/Exploiter)
```

---

## 五、环境保障与维护提示

1. **Tailscale 隧道保活**：
   三台主机均需确保 Tailscale 服务处于 `Connected` 状态，以便 100.x.x.x 虚拟内网保持通畅。
2. **Sudo 权限守则**：
   两台 Linux 机器账号均具有 Sudo 权限且必须输入密码（Kali: `kali`，Ubuntu: `wsad`），请不要将其改为免密 sudo，以防越权行为失控。
3. **PenAgent 代码兼容优化**：
   [`actions/remote_shell.py`](file:///C:/Users/Favor/Desktop/PenAgent/actions/remote_shell.py) 已针对 Kali Linux 的交互式 Shell（带 ANSI 终端颜色转义符和 Zsh 提示符）完成清洗与适配，保证命令下发与回显捕获无卡顿。
