# HermesPentBox

> **README Version: [English](README.md) | [简体中文](README_cn.md)**

AI 驱动的本地渗透测试工作台。浏览器流量汇入内置 MITM 代理，由 Agent 蜂群自动审计、出具意见并执行渗透——全程本地运行，与 Hermes Agent 深度集成。

> 仅限授权测试使用。

## 核心能力

- **流量** — HTTP/HTTPS MITM 抓包、WebSocket 帧捕获、站点地图同步 Neo4j
- **Agent 蜂群** — 10 个并行子 Agent 审计流量：漏洞判定、凭据提取、Nday 线索
- **三段式渗透模式** — 全自动（`/pentest` 主 Agent 全自动渗透）/ 被动（意见卡用户决策）/ 漏斗（纯审计 + 情报复合渗透）
- **审批官** — 独立审批 Agent 审计所有渗透与工具调用（任何站点可渗透，破坏性操作永远拒绝）
- **角色化模型管理** — 执行官 / 审计员 / 审批官 各自独立 LLM 模型配置
- **WebShell** — 生成/连接/虚拟终端/文件管理/Suo5 正向代理（哥斯拉/冰蝎/蚁剑）
- **代理链** — 上游代理 + 类 Burp 下游代理（HTTP/SOCKS5）
- **项目管理** — 类 Burp 二进制快照文件，每 10 秒自动保存，按项目数据隔离
- **操作日志** — 终端风格面板记录全部 Agent 操作

## 快速开始

```bash
npm install
npm start
```

| 服务 | 端口 |
|---|---|
| API / SSE | 8877 |
| 代理 | 8899 |
| 终端 WS | 8878 |
| Agent Bridge | 28766 |

前置：Node.js 24+ 与已配置模型的 Hermes CLI。

## 架构

```
浏览器 ──► MITM 代理 (8899) ──► 流量面板 / 站点地图 (Neo4j)
                 │  分析队列（子 Agent：审计员档案）
                 ▼
          意见卡 ──► Agent Bridge (28766) ──► Hermes AIAgent
                 │                            （执行官 / 审批官档案）
                 ▼
          漏洞库（项目快照）
```

## 合规声明

仅限授权测试使用。使用者须对测试目标拥有合法授权。

## 许可证

[MIT](LICENSE)
