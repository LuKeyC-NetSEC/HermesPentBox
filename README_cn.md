# HermesPentBox — AI 渗透工作台

> **语言**：中文 | [English](README.md)

基于 Electron 的桌面渗透测试工作台：内置 MITM 流量代理 + 浏览器控制（Chrome CDP / Firefox）+ 多子 Agent 蜂群式流量分析与渗透执行，通过**自研 Agent Bridge** 全程本地接入 Hermes 智能体，零配置。

> 仅用于**授权范围内**的渗透测试（客户合同 / SRC 众测 / 自研靶场）。使用者须对测试目标拥有合法授权。

---

## 功能

- **MITM 流量代理**（默认 8899 端口）：HTTP/HTTPS 双向抓包，自动信任内置 CA，支持 WebSocket 帧级捕获
- **浏览器控制**：Chrome / Firefox 一键接管，浏览器流量自动汇入流量面板
- **子 Agent 蜂群分析**：10 个并行子 Agent 自动分析流量，判定漏洞 / 提取敏感信息 / 提示 Nday 线索
- **渗透意见卡**：子 Agent 发现可疑目标自动推卡片，点击「进行渗透」即对**单个 API** 发起验证（严格单接口范围，不展开全站）
- **流式对话**：主 Agent 对话流式返回，跨轮续传记忆
- **Steer（运行中引导）**：Agent 运行中输入文字，按钮自动切换为 Steer——向运行中的任务注入引导而不中断
- **漏洞库管理**：渗透成果自动生成结构化漏洞文档（标题 / 危害等级 / 复现 / 原始请求响应包），常驻展示
- **全局情报共享**：多子 Agent 自动共享分析结论 / 已提取凭据 / 渗透成果，凭据自动生成「凭据利用」意见；同目标同方式自动去重，避免重复渗透
- **重发器（Repeater）**：HTTP/HTTPS/WS 自动识别协议，多标签页，Burp 风格重放
- **站点地图**：流量按域名/路径聚合视图
- **子 Agent 沟通窗口**：与单个子 Agent 对话查看渗透详情

## 架构

```
浏览器 (Chrome CDP / Firefox)
   │ 流量
   ▼
MITM 代理 (8899) ──► 流量面板 / 站点地图
   │ 分析队列
   ▼
10 × 子 Agent (Agent Bridge, 负载均衡分配)
   │ 渗透意见 (SSE)
   ▼
意见卡 ──「进行渗透」──► Agent Bridge (AIAgent)
   │                        chat / get_output / steer / interrupt
   ▼
漏洞库 (VULNDOC) / 全局情报 digest
```

- **主 API 服务**：8877（HTTP + SSE 事件流）
- **终端 WS**：8878
- **Agent Bridge**：28766（自研 TCP JSON-line 服务，自动拉起，使用 hermes-agent 的 `AIAgent` + `hermespentbox` 档案）

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

首次启动自动完成：启动 MITM 代理（8899）、生成 CA 证书、拉起自研 Agent Bridge（28766）。

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
| Agent Bridge | 28766 | 自研 TCP 桥接（自动拉起） |
| 上游代理 | 7890 | 可选（国内网络环境） |
| 子 Agent 槽 | 10 | 并行分析并发数 |

## 目录结构

```
electron/main.ts       应用入口（Electron 主进程）
core/proxy.ts          MITM 代理引擎（含 CA 生成/注入）
core/api.ts            主 API 服务（流量/分析/渗透/漏洞库/SSE/全局情报）
core/bridge.ts         Agent Bridge 客户端（TCP JSON-line：chat/steer/get_output/status/interrupt）
core/pentbox_bridge.py 自研 Agent Bridge 服务端（驱动 hermes-agent AIAgent）
core/browser.ts        Chrome CDP 控制
core/firefox.ts        Firefox 控制
core/ssh.ts            SSH 终端
core/persona.ts        子 Agent 人设与提示词
ui/app.js              前端界面（流量面板/意见卡/漏洞库/重发器/流式对话/Steer）
assets/                静态资源与技能包
```

## 常见问题

- **EADDRINUSE**：端口被残留进程占用，先 `taskkill /F /IM electron.exe` 并按端口清理 PID 再启动
- **curl 无法走代理**：Windows schannel 与 MITM 不兼容，用 `python urllib` + 信任 PentBox CA 代替
- **子 Agent 长时间转圈**：渗透为长任务（多步骤验证属正常）；界面现已显示工具进度与已工作时长，不再是无提示空白转圈。如确认异常可点击任务取消
- **Steer 引导被拒绝**：仅当目标 Agent 存在活跃运行时才会接受引导；空闲时按钮回退为 Send / Stop
