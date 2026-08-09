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
import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { spawn } from 'node:child_process'
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { connect } from 'node:net'
import { SOUL_PERSONA, USER_PROFILE } from './persona.ts'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'
import { HttpsProxyAgent } from 'https-proxy-agent'
import WebSocket from 'ws'
import { decodeBody } from './mitm.ts'
import os from 'node:os'
import type { FlowMeta, ProxyEngine, Upstream } from './proxy.ts'
import type { ChromeBrowser } from './browser.ts'
import type { FirefoxBrowser } from './firefox.ts'
import type { SshSession } from './ssh.ts'

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
    this.probeHermes()
    setInterval(() => this.probeHermes(), 5000)  // HERMES AGENT 状态实时探测
    this.loadVulns()
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
    if (f.method !== 'WS') this.enqueueAnalyze(f.id, f.detail, f.url)
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
  private analyzeMap = new Map<number, { state: 'queued' | 'analyzing' | 'done'; vuln?: boolean; level?: string; detail?: unknown; url?: string; sensitive?: { type: string; value: string }[] }>()
  /** 全局情报 digest：所有槽分析结论滚动汇总（注入每次分析 prompt——子 Agent 共享上下文，防记忆割裂） */
  private analysisDigest: string[] = []
  /** 已确认漏洞的 URL（基于全局情报去重：同 URL 不再重复推送渗透意见卡） */
  private vulnUrls = new Set<string>()
  /** 已渗透成功的 URL+渗透方式（渗透成果去重：同 API 同方式不再重复渗透；不同方式可再渗） */
  private penetratedKeys = new Set<string>()
  /** 进行中渗透的目标（slot → "Host+路径 方式"，供取消时写入全局情报） */
  private penetrateTargets = new Map<number, string>()
  /** 本地 hermes gateway 进程（渗透经 gateway 执行：取消走 WebSocket abort 信号，参考 hermes-studio chat-run 实现） */
  private gatewayProc: ReturnType<typeof spawn> | null = null

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

  /** 渗透经本地 gateway 执行（官方 api_server：POST /v1/runs 启动 → GET /v1/runs/{id}/events SSE 聚合 → 取消 = POST /v1/runs/{id}/stop，参考官方 desktop 后端实现） */
  private runViaGateway(input: string, sessionId: string | null, onChild?: (stop: () => void) => void): Promise<string> {
    const http = require('node:http') as typeof import('node:http')
    const fs = require('node:fs') as typeof import('node:fs')
    const key = (fs.readFileSync(join(this.hermesHome, '.env'), 'utf8').match(/API_SERVER_KEY=(.+)/) || [])[1]?.trim() || ''
    const base = { host: '127.0.0.1', port: 8642, headers: { Authorization: 'Bearer ' + key, 'content-type': 'application/json' } }
    const post = (path: string, body: unknown) => new Promise<{ code: number; body: string }>((resolve, reject) => {
      const data = JSON.stringify(body ?? {})
      const r = http.request({ ...base, path, method: 'POST', headers: { ...base.headers, 'content-length': Buffer.byteLength(data) } }, (res) => {
        let b = ''
        res.on('data', (d) => (b += d))
        res.on('end', () => resolve({ code: res.statusCode ?? 0, body: b }))
      })
      r.on('error', reject)
      r.write(data)
      r.end()
    })
    return new Promise((resolve, reject) => {
      this.ensureGateway().then(() => {
        post('/v1/runs', { input, session_id: sessionId ?? undefined, source: 'coding_agent' }).then((r) => {
          if (r.code !== 202) return reject(new Error(`run 启动失败：${r.code} ${r.body.slice(0, 120)}`))
          const runId = (r.body.match(/"run_id"\s*:\s*"([^"]+)"/) || [])[1]
          if (!runId) return reject(new Error('run_id 缺失'))
          let out = ''
          let finished = false
          const finish = (err?: Error) => { if (finished) return; finished = true; err ? reject(err) : resolve(out) }
          // 取消：POST /v1/runs/{id}/stop（官方停止端点，替代杀进程）
          onChild?.(() => { post(`/v1/runs/${runId}/stop`, {}).catch(() => {}); setTimeout(finish, 2000) })
          // SSE 事件流聚合（message.delta 文本 → run.completed 收尾）
          const ev = http.get({ ...base, path: `/v1/runs/${runId}/events` })
          ev.on('response', (res) => {
            let buf = ''
            res.on('data', (d) => {
              buf += d
              let idx
              while ((idx = buf.indexOf('\n\n')) >= 0) {
                const chunk = buf.slice(0, idx); buf = buf.slice(idx + 2)
                const line = chunk.split('\n').find((l) => l.startsWith('data:'))
                if (!line) continue
                let f
                try { f = JSON.parse(line.slice(5).trim()) } catch { continue }
                if (f.event === 'message.delta') out += f.text ?? f.delta ?? ''
                else if (f.event === 'run.completed') { if (f.output) out = f.output; finish() }
                else if (f.event === 'run.failed') finish(new Error(f.error || 'run failed'))
              }
            })
            res.on('end', () => finish())
            res.on('error', (e) => finish(new Error(`SSE 流错误：${e.message}`)))
          })
          ev.on('error', (e) => finish(new Error(`SSE 连接失败：${e.message}`)))
        }).catch((e) => reject(e))
      }).catch(reject)
    })
  }

  /** 新流量入分析队列（消息队列：FIFO，逐个消费；入队即快照完整请求/响应报文） */
  private enqueueAnalyze(id: number, detail?: unknown, url?: string): void {
    if (this.analyzeMap.has(id)) return
    // 浏览器自带流量（更新/字典/遥测/OCSP）：不送 Agent 直接 done（跳过 icon），不占 Hermes 队列
    if (this.isBrowserBuiltin(detail, url)) {
      this.analyzeMap.set(id, { state: 'done', vuln: false, builtin: true, detail, url })
      return
    }
    // 错误状态码：404（资源不存在）与 5xx（服务器错误）无 bypass 价值 → 跳过 Agent（done + 跳过 icon）
    // 401/403/407 等 40x 保留（可做 bypass 分析，必须发 Agent）
    const st = this.resStatus(detail)
    if (st === 404 || st >= 500) {
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
  ]

  private isBrowserBuiltin(detail?: unknown, url?: string): boolean {
    const s = (typeof detail === 'string' ? detail : JSON.stringify(detail ?? '')) + ' ' + (url ?? '')  // url 参与匹配（detail 无路径时黑名单 URL 规则仍命中）
    if (!s.trim()) return false
    return ApiServer.BROWSER_TRAFFIC.some((re) => re.test(s))
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
    if (!existsSync(this.hermesCli)) { this.hermesOnline = false; return }
    let done = false
    const set = (v: boolean) => { if (!done) { done = true; this.hermesOnline = v } }
    // desktop 后端端口（18765=backend，18766=内部桥），任一可连即在线
    for (const port of [18765, 18766]) {
      const s = connect({ host: '127.0.0.1', port, timeout: 800 })
      s.once('connect', () => { s.destroy(); set(true) })
      s.once('error', () => s.destroy())
      s.once('timeout', () => s.destroy())
      s.setTimeout(800)
      // 全部失败后（两连接都 error/timeout）置离线
      setTimeout(() => { if (!done) set(false) }, 900)
    }
  }
  private hermesSessionId: string | null = null
  private hermesBusy = false
  /** 10 个子 Agent 独立会话槽（并行分析互不干扰；每槽 --resume 各自累积上下文） */
  private analyzeSlots: (string | null)[] = new Array(ApiServer.MAX_PARALLEL).fill(null)
  /** 每槽当前 in-flight 数（负载均衡：新流量分给最空闲的子 Agent，最少连接算法） */
  private slotBusy: number[] = new Array(ApiServer.MAX_PARALLEL).fill(0)
  /** 进行中的渗透子 Agent 进程（slot → child，供 /api/penetrate/cancel 杀进程） */
  private penetrateChildren = new Map<number, ReturnType<typeof spawn> | (() => void)>()

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
  private hermesChat(message: string): Promise<string> {
    return this.runHermes(message, this.chatSessionId, (sid) => { this.chatSessionId = sid })
  }

  /** 调本地 Hermes 分析一条流量（异步 spawn 不阻塞主进程）：首次建会话（抓 session_id），之后 --resume 同一会话；返回含 slot（提出意见的子 Agent 槽位） */
  private hermesAnalyze(detail: unknown): Promise<{ vuln: boolean; level: string; sensitive: { type: string; value: string }[]; advice: string; slot: number }> {
    const d = (detail ?? {}) as Record<string, unknown>
    const digest = this.analysisDigest.length
      ? `【全局情报】此前其他分析已发现：\n${this.analysisDigest.join('\n')}\n（结合这些情报判断当前流量是否与已知发现关联、是否同一目标的其他风险面）\n\n`
      : ''
    const prompt = digest + '分析以下 HTTP 流量（完整请求/响应）：\n1. 判断是否存在可利用的安全漏洞；\n2. 提取流量中的可利用敏感信息，分三类：\n   a) 攻击凭据：API Key / Bearer Token / Access Token / Password / Secret / Session Cookie / Private Key / Cloud Access Key / Authorization 等；\n   b) 敏感个人信息：手机号(type=Phone) / 身份证号(type=ID Card) / 银行卡号(type=Bank Card) / Email 等；\n   c) Nday 线索：疑似存在已知漏洞 CVE 的 API 路径/组件/版本、可疑 JS 引用 → type 用 "Nday API" / "Nday JS" / "Nday 组件"。\n3. 若存在可利用漏洞（vuln=true），输出渗透意见 advice，格式必须为："经 Hermes 分析 <API路径> 可进行 <攻击方式> 渗透，是否进行"（攻击方式用具体手法：SQL 注入/未授权访问/SSRF/暴力破解/越权等）。注意：vuln=true 时 advice 必填，禁止输出空字符串。\n只输出一行 JSON，格式：{"vuln": true或false, "level": "high|medium|low|info", "sensitive": [{"type": "类型", "value": "值"}], "advice": "渗透意见或空"}。无漏洞时 advice 为空字符串。\n\n【请求】\n' +
      `${d.reqLine ?? ''}\n${((d.reqRawHeaders as string[]) ?? []).join('\n')}\n\n${d.reqBody ?? ''}\n\n【响应】\n${d.resLine ?? ''}\n${((d.resRawHeaders as string[]) ?? []).join('\n')}\n\n${String(d.resBody ?? '').slice(0, 4000)}`
    // 负载均衡：选当前最空闲的子 Agent 槽（最少连接算法），而非静态轮转
    // 渗透中的槽不接新流量分析（Agent 提出渗透意见后专注渗透；超时/取消/完成后再恢复分配）
    const busy = this.slotBusy.map((v, i) => (this.penetrateTargets.has(i) ? Infinity : v))
    const slot = busy.indexOf(Math.min(...busy))
    this.slotBusy[slot]++
    const sid = this.analyzeSlots[slot]
    // spawn 不经 shell：prompt 含 | 等字符安全；session_id 在 stderr，需合并捕获
    const args = ['chat', '-q', prompt, '-Q', '--source', 'pentbox-analyzer']
    if (sid) args.push('--resume', sid)
    return new Promise((resolve, reject) => {
      const child = spawn(this.hermesCli, args, { timeout: 240000, env: this.hermesEnv, cwd: this.agentCwd, windowsHide: true })
      let out = ''
      child.stdout.on('data', (b) => { out += b })
      child.stderr.on('data', (b) => { out += b })
      child.on('error', reject)
      child.on('close', () => {
        this.slotBusy[slot]--
        const newSid = out.match(/session_id:\s*(\S+)/)?.[1]
        if (newSid) this.analyzeSlots[slot] = newSid
        const p = this.extractJson(out)
        const sens: { type: string; value: string }[] = Array.isArray(p?.sensitive) ? p.sensitive.filter((s: unknown) => s && typeof s === 'object' && (s as { value?: unknown }).value != null).map((s) => ({ type: String((s as { type?: unknown }).type ?? 'Secret'), value: String((s as { value?: unknown }).value).slice(0, 200) })) : []
        let advice = p && typeof p.advice === 'string' && p.advice ? p.advice.slice(0, 300) : ''
        // 兜底：模型判有漏洞但 advice 空（输出不稳定）→ 用请求路径生成渗透意见（保证意见卡出现）
        if (p?.vuln && !advice) {
          const pm = String(d.reqLine ?? '').match(/\S+\s+(\S+)/)
          advice = `经 Hermes 分析 ${pm ? pm[1] : '目标'} 可进行 安全测试 渗透，是否进行`
        }
        resolve({ vuln: p ? !!p.vuln : false, level: p?.level ?? 'info', sensitive: sens, advice, slot })
      })
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
            // 全局情报 digest：有发现的结论入滚动汇总（子 Agent 共享上下文）
            if (r.vuln || r.sensitive?.length) {
              const u = st.url || ''
              const line = `${u}：${r.vuln ? `漏洞(${r.level})` : ''}${r.advice ? ` 意见:${r.advice.slice(0, 60)}` : ''}${(r.sensitive || []).slice(0, 3).map((s) => ` 敏感[${s.type}:${String(s.value).slice(0, 40)}]`).join('')}`.slice(0, 300)
              this.analysisDigest.push(line)
              if (this.analysisDigest.length > 20) this.analysisDigest.splice(0, this.analysisDigest.length - 20)  // 最多 20 条（token 可控）
            }
            // 渗透意见 → SSE 推送（前端 Hermes Agent 聊天框渲染意见卡：进行/取消/回复；slot 绑定提出意见的子 Agent，进行渗透由该子 Agent 执行）
            // 基于全局情报去重：同 URL 已确认漏洞（vulnUrls）→ 不再重复推送；同 URL 同方式已渗透过（penetratedKeys）→ 不再推送（发卡前查重，避免重复任务）
            if (r.advice) {
              const u = st.url || ''
              const pm = r.advice.match(/可进行\s*(.+?)\s*渗透/)?.[1] || ''
              if (!(r.vuln && u && this.vulnUrls.has(u)) && !(u && this.penetratedKeys.has(`${u}|${pm}`))) {
                this.pushSse({ type: 'analyze-advice', id, advice: r.advice, level: r.level, slot: r.slot })
                if (r.vuln && u) this.vulnUrls.add(u)
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

  private saveVulns(): void {
    try {
      const { writeFileSync, mkdirSync } = require('node:fs') as typeof import('node:fs')
      const { dirname } = require('node:path') as typeof import('node:path')
      mkdirSync(dirname(this.vulnFile), { recursive: true })
      writeFileSync(this.vulnFile, JSON.stringify(this.vulns, null, 2))
    } catch { /* 落盘失败不阻断 */ }
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
    // 经内置代理 8899（http 绝对路径 / https CONNECT via HttpsProxyAgent）；带标记头 → 代理转发但不记录流量
    outHeaders['x-pentbox-source'] = 'repeater'
    const proxy = `http://127.0.0.1:${this.opts.proxyPort ?? 8899}`
    const resp = await new Promise<{ statusLine: string; headers: string[]; body: string }>((resolve, reject) => {
      const done = (res: IncomingMessage) => {
        const chunks: Buffer[] = []
        res.on('data', (c: Buffer) => { if (chunks.join('').length < 262144) chunks.push(c) })
        res.on('end', () => {
          const buf = Buffer.concat(chunks)
          const rawLines: string[] = []
          for (let i = 0; i + 1 < res.rawHeaders.length; i += 2) rawLines.push(`${res.rawHeaders[i]}: ${res.rawHeaders[i + 1]}`)
          resolve({ statusLine: `HTTP/${res.httpVersion} ${res.statusCode} ${res.statusMessage}`, headers: rawLines, body: decodeBody(buf, (res.headers['content-encoding'] as string) || undefined) })
        })
        res.on('error', reject)
      }
      const opts = { method, headers: outHeaders, signal: AbortSignal.timeout(20000) } as any
      if (url.protocol === 'https:') {
        opts.agent = new HttpsProxyAgent(proxy)
        opts.rejectUnauthorized = false // 经 MITM 终止，node 不认系统 CA
        opts.hostname = url.hostname
        opts.port = Number(url.port || 443)
        opts.path = url.pathname + url.search
        httpsRequest(opts, done).on('error', reject).end(body)
      } else {
        opts.host = '127.0.0.1'
        opts.port = this.opts.proxyPort ?? 8899
        opts.path = url.href
        httpRequest(opts, done).on('error', reject).end(body)
      }
    })
    // 重发器流量不进应用流量表（代理侧已按标记头跳过记录；这里不再主动 push）
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
          const body = JSON.parse(await this.readBody(req)) as { message: string }
          if (!body.message) throw new Error('empty message')
          const reply = await this.hermesChat(body.message)
          this.json(res, 200, { reply, sessionId: this.analyzeSlots[0] })
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
          this.json(res, 200, { ok: true, engine })
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
            this.json(res, 200, { ok: true })
          } else if (req.method === 'DELETE') {
            this.vulns = this.vulns.filter((x) => x.id !== id)
            this.saveVulns()
            this.json(res, 200, { ok: true })
          } else { this.json(res, 405, { error: 'method not allowed' }) }
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
          const body = JSON.parse(await this.readBody(req)) as { advice?: string; slot?: number; reqRaw?: string; resRaw?: string }
          if (!body.advice) throw new Error('advice 缺失')
          const slot = typeof body.slot === 'number' && body.slot >= 0 && body.slot < ApiServer.MAX_PARALLEL ? body.slot : 0
          // 渗透前查重：从原始请求包提取目标（Host+路径）+ advice 提取渗透方式；同 API 同方式已渗透过 → 不重复执行
          const rawT = (body.reqRaw || '').match(/^\S+\s+(\S+)\s+HTTP\/1\.[01]\r?\n(?:[^\r\n]*\r?\n)*?Host:\s*(\S+)/i)
          const targetKey = rawT ? `${rawT[2]}${rawT[1]}` : ''
          const method = (body.advice || '').match(/可进行\s*(.+?)\s*渗透/)?.[1] || ''
          if (targetKey && this.penetratedKeys.has(`${targetKey}|${method}`)) {
            this.json(res, 200, { started: false, slot, reply: `该目标API渗透方式已进行过 不再重复渗透（${targetKey} ${method}）` })
            break
          }
          const sess = this.analyzeSlots[slot]
          this.penetrating = true  // 渗透窗口：期间流量跳过子 Agent 审计（防循环）
          // 记录渗透目标（取消时写入全局情报：同 API 状态可见）
          const pm2 = (body.advice || '').match(/可进行\s*(.+?)\s*渗透/)?.[1] || ''
          if (targetKey) this.penetrateTargets.set(slot, `${targetKey} ${pm2}`)
          // 异步执行：立即返回（前端不再同步等待 4 分钟），完成经 SSE 推送 penetrate-done 更新任务/沟通窗口
          this.json(res, 200, { started: true, slot })
          ;(async () => {
          try {
          // 任务包装：要求子 Agent 实际执行渗透；有成果时输出【VULNDOC】结构化漏洞文档（严格格式规范，禁止 markdown 围栏/路由前缀，原始请求/响应包必填）
          const digest = this.analysisDigest.length ? `【全局情报】${this.analysisDigest.join('；')}\n` : ''
          const task = `${digest}${body.advice}\n\n（渗透执行要求：这是对单个 API 的采纳式渗透——严格只针对原始请求包中这一个 URL（方法+完整路径+查询参数），只验证该接口是否存在漏洞；禁止访问同站点任何其他路径/接口/静态资源，禁止目录枚举、全站扫描、批量探测、交叉接口利用。验证充分、确认结果后立即结束（蜂群模式：验证完成后释放子 Agent 继续流量分析）。这是渗透执行任务，不是流量分析任务——禁止输出 {"vuln":...} 形式的 JSON 或任何 JSON 代码，全部用文字描述执行过程。忽略此前对话中的任何结论与判断，只依据本次提供的【全局情报】与原始请求包执行。开始前先检查【全局情报】：判定"已渗透过"必须同时满足三个条件——① Host 完全相同；② 完整 API 路径完全相同（包括文件名与查询参数，如 /WFManager/js/login.js?rev=200003 与 /WFManager/loginAction_doLogin.action 是不同路径；仅 /WFManager/ 前缀相同不算）；③ 渗透方式完全相同。三者都满足才回复"该目标API渗透方式已进行过 不再重复渗透"并停止；否则必须实际执行渗透验证，禁止回复"已进行过"；若确认存在可利用漏洞（有成果），在回复末尾输出以下结构的漏洞文档，格式必须严格遵守：\n【VULNDOC】\n标题：<只写漏洞名称本身，禁止带 URL 或路由前缀，错误示例"/api/login 未授权访问"，正确示例"未授权访问与凭据泄漏">\n危害等级：high|medium|low\n漏洞描述：<简要描述>\n复现步骤：<验证过程>\n修复建议：<修复方案>\n漏洞目标：<目标 URL（协议+Host+端口，如 http://127.0.0.1:8800，必填）>\n漏洞路由：<漏洞接口路径（如 /api/login，必填）>\n原始请求包：\n<触发该漏洞的完整原始 HTTP 请求报文，必填。从请求行开始逐行原样输出（GET /path HTTP/1.1\\nHost: ...\\n\\n<body>），禁止使用 markdown 代码块围栏（禁止 \`\`\` 字符）、禁止加引号包裹、禁止 JSON 转义，必须可直接复制重放>\n原始响应包：\n<对应的完整原始 HTTP 响应报文，必填。从状态行开始逐行原样输出（HTTP/1.1 200 OK\\nHeader: ...\\n\\n<body>），同样禁止 \`\`\` 与任何修饰字符>\n若未确认漏洞，只需输出执行过程说明，不要输出【VULNDOC】）`
          const reply = await this.runViaGateway(task, sess, (abort) => { this.penetrateChildren.set(slot, abort) })  // 渗透经本地 gateway 执行（取消 = WebSocket abort，参考 hermes-studio chat-run）
          this.penetrateChildren.delete(slot)
          this.penetrateTargets.delete(slot)  // 渗透正常完成：清除目标记录（取消记录只由 cancel 路径写入全局情报）
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
            // 渗透成果写入全局情报（子 Agent 共享：后续分析/渗透前可见，避免同 API 同方式重复渗透）
            if (uri) {
              const pm = (body.advice || '').match(/可进行\s*(.+?)\s*渗透/)?.[1] || ''
              // 去协议统一格式（与渗透前 reqRaw 提取的 targetKey 一致：无协议 Host+路径）——否则后端查重 miss
              this.penetratedKeys.add(`${uri.replace(/^https?:\/\//i, '')}|${pm}`)
              // 去协议统一格式（如 http://127.0.0.1:8800/api/login → 127.0.0.1:8800/api/login）——子 Agent 对比当前目标（reqRaw Host+路径，无协议）不误判
              this.analysisDigest.push(`渗透成果: ${uri.replace(/^https?:\/\//i, '')}（${pm}）漏洞(${level}) ${v.name}`)
            }
            this.pushSse({ type: 'vuln-doc', vuln: { id: v.id, name: v.name, level: v.level, desc: v.desc, exploit: v.exploit, ts: v.ts } })
            // 静默注入主 Agent 会话（仅记录到上下文，主 Agent 记住所有 vuln；不回复不执行）
            this.runHermes(`（记忆记录，无需回复与执行任何操作）已知漏洞档案：漏洞 ${v.id}：${v.name}（${level}）\n描述：${g('漏洞描述').slice(0, 300)}\n复现：${g('复现步骤').slice(0, 300)}`, this.chatSessionId, (sid) => { this.chatSessionId = sid }).catch(() => { /* 记忆注入失败不影响主流程 */ })
          }
          this.pushSse({ type: 'penetrate-done', slot, reply, vulnDoc: !!docBody })  // 异步完成通知（前端更新任务/沟通窗口）
          } catch (e) {
            this.pushSse({ type: 'penetrate-done', slot, reply: `（渗透执行失败：${(e as Error).message}）`, vulnDoc: false })
          } finally { this.penetrating = false }  // 结束渗透窗口（无论成败都恢复审计）
          })()
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
          if (ptarget) { this.analysisDigest.push(`已取消渗透: ${ptarget}（用户中断）`); this.penetrateTargets.delete(slot) }
          this.penetrating = false  // 取消即恢复流量审计（防 kill 后 close 未触发的极端情况）
          this.analyzeSlots[slot >= 0 && slot < ApiServer.MAX_PARALLEL ? slot : 0] = ''  // 释放槽位会话：下次分析新建干净会话，继续流量分析工作
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
