# HermesPentBox

AI 驱动的本地渗透测试工作台。浏览器流量汇入内置 MITM 代理，由 Agent 蜂群自动分析、出具意见卡并执行单点渗透验证——全程本地运行，与 Hermes Agent 深度集成。

> 仅限授权测试使用。

## 核心能力

- **流量** — HTTP/HTTPS MITM 抓包、WebSocket 帧捕获、站点地图同步 Neo4j
- **分析** — 10 个并行子 Agent 审计流量：漏洞判定、凭据提取、Nday 线索
- **渗透** — 意见卡一键单点验证，成果自动写入漏洞库
- **情报共享** — Neo4j 会话图（主机/接口/漏洞/凭据/Shell）跨 Agent 共享，同目标去重
- **WebShell** — 生成/连接/虚拟终端/文件管理/Suo5 正向代理（哥斯拉/冰蝎/蚁剑/自定义）
- **代理链** — 上游代理 + 类 Burp 下游代理（HTTP/SOCKS5）
- **浏览器控制** — 一键接管 Chrome CDP / Firefox
- **项目管理** — 类 Burp 项目文件：二进制快照自动保存、项目管理、按项目数据隔离

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
                 │  分析队列（10 子 Agent）
                 ▼
          意见卡 ──► Agent Bridge (28766) ──► Hermes AIAgent
                 │
                 ▼
          漏洞库（项目快照）
```

## 技术栈

Electron · Node.js · esbuild · Neo4j · xterm.js · Hermes Agent · V8 二进制项目快照

## 合规声明

仅限授权测试使用（SRC / 众测 / 自建靶场）。使用者须对测试目标拥有合法授权。
