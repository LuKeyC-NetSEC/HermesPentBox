# HermesPentBox

> **AI 驱动的本地渗透测试工作台** · AI-Powered Local Pentest Workbench

[English](README.md) · 仅限**授权测试**使用（SRC / 众测 / 自建靶场）。

一体化桌面工作台：内置 MITM 代理抓包 → 子 Agent 蜂群自动分析 → 意见卡 → 单点渗透验证，全程本地运行，与 Hermes Agent 通过自研 Bridge 零配置协作。

---

## Features

| 领域 | 能力 |
|---|---|
| **流量与分析** | HTTP/HTTPS MITM 抓包（8899）、WebSocket 帧捕获、站点地图（Neo4j 同步） |
| **Agent 蜂群** | 10 个并行子 Agent 自动审计流量：漏洞判定 / 敏感信息提取（HaENet 标签）/ Nday 线索 |
| **渗透执行** | 意见卡一键「进行渗透」，严格单 API 作用域；成果自动生成 VULNDOC 写入漏洞库 |
| **情报共享** | Neo4j 会话图（Host/Api/Vuln/Cred/Shell）跨 Agent 共享，同目标去重防重复渗透 |
| **WebShell 管理** | 全类型生成/连接/虚拟终端/文件管理/Suo5 正向代理（Godzilla·Behinder·AntSword·Custom） |
| **代理链** | 上游代理 + 类 Burp 下游代理（HTTP/SOCKS5，IP/端口自定义，重启保留） |
| **浏览器控制** | Chrome CDP / Firefox 一键接管，流量自动汇入面板；类 Burp CA 证书信任方案 |
| **Repeater / 终端 / SSH** | HTTP/HTTPS/WS 多标签重发器、xterm 虚拟终端、SSH 会话 |

## Quick Start

```bash
npm install
npm start          # build + 启动（首次自动启动代理/Bridge/CA 生成）
```

- 主 API：`8877` · 代理：`8899` · Terminal WS：`8878` · Agent Bridge：`28766`
- 前置：Node.js 24 + Hermes CLI（已配置模型）

## Architecture

```
Browser (Chrome/Firefox) ──► MITM Proxy (8899) ──► 流量面板 / 站点地图(Neo4j)
                                   │ 分析队列（10 子 Agent，负载均衡）
                                   ▼
                          意见卡(SSE) ──「进行渗透」──► Agent Bridge (28766)
                                   │                        │
                                   ▼                        ▼
                          漏洞库 (VULNDOC)              Hermes AIAgent
```

## Stack

Electron · Node.js · Neo4j · esbuild · xterm.js · hermes-agent (AIAgent) · Godzilla/Behinder 协议库

## License

仅限**授权测试**使用（客户合同 / SRC 众测 / 自研靶场）。使用者须对测试目标拥有合法授权。
