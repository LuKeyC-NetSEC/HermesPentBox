---
name: pentbox-workbench-api
description: "HermesPentBox 工作台内置 API 手册：WebShell 管理、HTTP 历史流量表、站点地图 三大模块的完整接口调用规范。Use when you need to read/execute/manage WebShell sessions, inspect captured HTTP/WebSocket traffic, or enumerate the site map of the current target."
metadata:
  hermes:
    tags: [pentbox, api, webshell, traffic, sitemap]
    related_skills: ["hacker-webshell-webshell-connect", "hacker-sqli-sql-injection", "hacker-injection-checking"]
---

# SKILL: HermesPentBox 工作台 API — WebShell 管理 / HTTP 历史流量 / 站点地图

> **AI LOAD INSTRUCTION**: 本 skill 是 HermesPentBox 工作台三大模块的 API 使用手册。工作台 API 基址 `http://localhost:8877`（同机本进程），全部走 HTTP + JSON。所有接口**只读或执行**，遵守工作台安全边界：破坏性/不可逆操作会被审批官拦截（执行接口会过审批，需在请求中描述清楚验证意图）。

## 0. 通用约定

- **基址**：`http://localhost:8877`（同机，无鉴权）
- **编码**：全部 UTF-8 JSON；`Content-Type: application/json`
- **执行类接口**（WebShell 命令/文件删除）会经过**审批官 Agent 审计**：描述清楚命令的只读/验证意图即会被批准；破坏性操作（删库/rm -rf/格式化/勒索/数据外泄管道）会被拒绝
- 时间戳 `ts` 为毫秒；`status` 取值 `alive/dead/unknown`

## 1. WebShell 管理

### 1.1 列表 / 新增
```
GET  /api/webshells                        → { items: [{id,type,script,url,status,ts,cryption,payload,encoding,headers,remark}] }
POST /api/webshells                        → 新增 { type:"godzilla|behinder|antsword", script:"php|jsp|jspx|asp|aspx", url, password, key, cryption?, payload?, encoding?, headers?, remark? } → { ok, id }
```
- `type` 仅支持 `godzilla`/`behinder`/`antsword`（custom 已移除）
- 列表返回的 `password/key` 已脱敏为 `***`；需真实值用 detail

### 1.2 详情 / 修改 / 删除
```
GET    /api/webshells/detail?id=N          → 完整 WebShell（含真实 password/key）
PUT    /api/webshells/detail?id=N          → 修改 { type?,script?,url?,password?,key?,cryption?,payload?,encoding?,headers?,remark?,timeout? } → { ok }
DELETE /api/webshells/detail?id=N          → 删除（同时从图移除）→ { ok }
```

### 1.3 存活探测
```
POST /api/webshells/ping      { id }                    → { alive, error? }（HTTP 可达性，更新 status）
POST /api/webshells/alive     { id }                    → { alive, detail?, error? }（协议级存活：哥斯拉 test 协议 / 其他类型执行标识命令）
POST /api/webshells/alive_all                           → { items: [{id,url,alive,error?}] }（全部批量存活）
POST /api/webshells/test      { url, type?, script?, password?, key?, cryption?, payload?, encoding?, headers? } → { alive, detail?, error? }（不落库的直测）
```

### 1.4 命令执行（核心）
```
POST /api/webshells/exec     { id, command }            → { ok, output }（成功） / { ok:false, error }（失败或被审批拦截）
```
- **优先使用本接口执行命令/读取主机信息**，不要自行实现加解密协议（哥斯拉 XOR+base64/AES-ECB、冰蝎 AES-CBC、蚁剑 base64 的握手与密钥细节极易出错）
- 命令如 `id`/`whoami`/`cat /etc/passwd`/`ls -la`/`ifconfig`/`netstat -an` 属只读验证，审批官会批准
- 破坏性命令（`rm -rf`、删库、格式化、`shutdown`）会被审批拦截

### 1.5 文件操作
```
POST /api/webshells/fileop   { id, action, ... }         → { output }
  action="list"   { dir }       列出目录（哥斯拉返回 ok\n路径\n名字\t文件1/0\t时间\t大小\t权限）
  action="read"   { file }      读文件内容
  action="write"  { file, content(base64) }  写/上传文件
  action="delete" { file }      删除文件（不可逆，Agent 调用会被审批官审计）
```

### 1.6 生成与正向代理
```
POST /api/webshells/generate  { type:"godzilla|behinder|antsword", payload?, script?, cryption?, password, key?, evasion? }
                              → { ok, code（生成的 shell 代码）, script, payload, note }
POST /api/webshells/suo5      { id, url, action:"start|stop|status", dir?, name?, port? } → Suo5 正向代理（SOCKS5 本地端口）
```

## 2. HTTP 历史流量表

### 2.1 流量列表（分页/搜索）
```
GET /api/flows?limit=50&after=0&q=keyword      → { items:[{id,method,url,status,resLen,ts,builtin,skipped}], next }
```
- `after` 增量游标（只取 id > after）；`q` 关键字过滤 method+url；`builtin/skipped` 标记浏览器内置/错误码流量（站点地图已排除）
- 最新流量在 items 末尾（`slice(-limit)`），取最后 N 条即最新

### 2.2 单条完整报文
```
GET /api/flows/{id}/detail                       → { reqLine, reqRawHeaders[], reqBody, resLine, resRawHeaders[], resBody, reqHeaders{}, resHeaders{} }
```
- 分析漏洞/凭据时用此接口取完整请求/响应包

### 2.3 聚合读取（HTTP + WebSocket 一次拿）
```
GET /api/traffic?limit=20&full=1                 → { total, wsTotal, http:[FlowMeta(或 full 带 detail.request/response)], ws:[{ts,direction,payload,length}] }
```
- `full=1` 时每条带完整 `detail.request` / `detail.response` 原始报文——**审计最近流量首选**

### 2.4 清空 / 实时流
```
POST /api/flows/clear                            → 清空历史（慎用）
GET  /api/events                                 → SSE 实时事件流（flow 新流量 / analyze-advice 意见卡 / vuln-doc 成果 / log 操作日志 / penetrate-done）
```

## 3. 站点地图

工作台站点地图**由流量自动构建**（按 Host → 路径树），无独立 API——两种方式获取：

### 3.1 图情报（推荐，站点地图的语义版本）
```
GET /api/graph/query?format=json                 → 结构化图：Host/Api/Vuln/Cred/WebShell/Analysis 节点与关系
GET /api/graph/query?format=json&host=example.com → 只看该主机的节点
GET /api/graph/query                             → 图情报文本（与注入 prompt 同格式）
```
- 图节点带 `project` 属性（当前项目隔离）；包含已确认漏洞、凭据、WebShell 等 Agent 共享情报

### 3.2 从流量构建
```
GET /api/flows?limit=1000                        → 拉全量流量，按 url 的 host+path 自行分组即得站点地图
```
- 规则：`new URL(url).hostname` 为一级（Host），`pathname` 分段为路径树；排除 `builtin/skipped` 流量

## 4. 典型工作流示例

1. **审计最新流量**：`GET /api/traffic?limit=50&full=1` → 逐条看请求/响应
2. **提取敏感信息**：分析响应体中的 token/密钥/路径；用 `POST /api/graph/note {host,path,text,level:"high"}` 记录情报（图共享）
3. **WebShell 操作**：`GET /api/webshells` 找存活会话 → `POST /api/webshells/exec {id,command:"id"}` 执行 → 读文件用 fileop read
4. **构建站点地图**：`GET /api/graph/query?format=json` 获取主机/接口清单 → 对未测接口发起验证
