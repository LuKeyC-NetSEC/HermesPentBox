# HermesPentBox — AI 渗透工作台

> **语言**：中文 | [English](README.md)

基于 Electron 的桌面渗透测试工作台：内置 MITM 流量代理 + 浏览器控制（Chrome CDP / Firefox）+ 多子 Agent 蜂群式流量分析与渗透执行，全程本地部署、零配置接入 Hermes 智能体。

> 仅用于**授权范围内**的渗透测试（客户合同 / SRC 众测 / 自研靶场）。使用者须对测试目标拥有合法授权。

---

## 功能

- **MITM 流量代理**（默认 8899 端口）：HTTP/HTTPS 双向代理，自动信任内置 CA（`PentBox MITM Root CA`），支持 WebSocket 帧级流量捕获
- **浏览器控制**：Chrome CDP（默认 9334）/ Firefox 一键接管，浏览器流量自动汇入流量面板
- **子 Agent 蜂群分析**：10 个并行子 Agent 槽，流量自动负载均衡分发分析（漏洞判定 / 敏感信息提取 / Nday 线索）
- **渗透意见卡**：子 Agent 提出意见后以卡片形式推送，点击「进行渗透」= 采纳对**单个 API** 的渗透意见，由对应子 Agent 快速验证（严格单 API 范围，不展开全站）
- **渗透执行经本地 Hermes Gateway**：官方 `api_server`（POST /v1/runs 启动 → SSE 聚合 → POST stop 优雅取消），不杀进程
- **漏洞库管理**：渗透成果自动写入漏洞库（VULNDOC 结构化文档：标题 / 危害等级 / 复现步骤 / 原始请求响应包），成果卡替换建议卡常驻展示
- **全局情报**：子 Agent 分析结论 / 渗透成果 / 取消记录汇总注入，供后续子 Agent 决策（防重复渗透：Host+完整路径+方式三条件查重）
- **重发器（Repeater）**：HTTP/HTTPS/WS 自动识别协议，多标签页，Burp 风格交互
- **站点地图**：流量聚合视图，按域名/路径组织
- **子 Agent 沟通窗口**：与单个子 Agent 对话查看渗透详情

## 架构

```
浏览器 (Chrome CDP / Firefox)
   │ 流量
   ▼
MITM 代理 (8899) ──► 流量面板 / 站点地图
   │ 分析队列
   ▼
10 × 子 Agent (hermes chat -q, 负载均衡分配)
   │ 渗透意见 (SSE)
   ▼
意见卡 ──「进行渗透」──► 本地 Hermes Gateway (8642 api_server)
   │                        POST /v1/runs + SSE events + POST stop
   ▼
漏洞库 (VULNDOC) / 全局情报 digest
```

- **主 API 服务**：8877（HTTP + SSE 事件流）
- **终端 WS**：8878
- **Hermes Gateway**：`hermes gateway run`（自动拉起，api_server 平台，`API_SERVER_KEY` 认证）

## 快速开始

### 环境要求

- Node.js 24（LTS）
- 已安装 Hermes CLI（`hermes` 在 PATH），并配置好模型 Provider

### 安装与启动

```bash
npm install
npm run build     # esbuild 打包 electron/main.ts → out/main.cjs
npm start         # build + 启动应用
# 或直接：
npx electron .
```

首次启动自动完成：启动 MITM 代理（8899）、生成 CA 证书、拉起本地 Hermes Gateway（8642）。

### 测试

```bash
node node_modules/tsx/dist/cli.mjs core/proxy.test.ts
node node_modules/tsx/dist/cli.mjs core/api.test.ts
```

> 注意：测试会占用 8899 等端口，运行前需先退出应用实例。

## 配置

| 项 | 默认 | 说明 |
|---|---|---|
| API 端口 | 8877 | 主 HTTP API + SSE |
| 代理端口 | 8899 | MITM 代理 |
| CDP 端口 | 9334 | Chrome 远程调试 |
| 终端 WS | 8878 | 终端面板 |
| Gateway 端口 | 8642 | 本地 Hermes api_server（自动拉起） |
| 上游代理 | 7890 | 可选（国内网络环境） |
| 子 Agent 槽 | 10 | 并行分析并发数 |

## 目录结构

```
electron/main.ts       应用入口（Electron 主进程）
core/proxy.ts          MITM 代理引擎（含 CA 生成/注入）
core/api.ts            主 API 服务（流量/分析/渗透/漏洞库/SSE）
core/browser.ts        Chrome CDP 控制
core/firefox.ts        Firefox 控制
core/ssh.ts            SSH 终端
core/persona.ts        子 Agent 人设与提示词
ui/app.js              前端界面（流量面板/意见卡/漏洞库/重发器）
assets/                静态资源与技能包
```

## 常见问题

- **EADDRINUSE**：端口被残留进程占用，先 `taskkill /F /IM electron.exe` 并按端口清理 PID 再启动
- **curl 无法走代理**：Windows schannel 与 MITM 不兼容，用 `python urllib` + 信任 PentBox CA 代替
- **子 Agent 长时间转圈**：渗透为长任务（多步骤验证属正常）；如确认异常可点击任务取消（走 Gateway `POST /v1/runs/{id}/stop` 优雅停止）
