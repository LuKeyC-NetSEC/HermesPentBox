/**
 * HermesPentBox 代理引擎
 * 传统 HTTP 代理：普通请求转发 + CONNECT 隧道，支持上游链（直连/HTTP/SOCKS4/5）
 * 每个流事件通过 onFlow 回调发出 → api.ts 转 SSE → Hermes / UI 消费
 */
import { createServer, request as httpRequest, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { connect as netConnect, type Socket } from 'node:net'
import { SocksProxyAgent } from 'socks-proxy-agent'
import { HttpProxyAgent } from 'http-proxy-agent'
import { SocksClient } from 'socks'
import { execSync } from 'node:child_process'
import { mitmTunnel, decodeBody } from './mitm.ts'

export type Upstream =
  | { type: 'direct' }
  | { type: 'http' | 'https'; host: string; port: number; username?: string; password?: string }
  | { type: 'socks4' | 'socks5' | 'socks5h'; host: string; port: number; username?: string; password?: string }

export interface FlowMeta {
  id: number
  ts: number
  method: string
  url: string
  status: number
  bytes: number
  upstream: string
  error?: string
  /** MITM 全量报文（请求/响应头+体）——不随列表/SSE 传输，走 /api/flows/:id/detail */
  detail?: {
    reqHeaders: Record<string, string>; reqBody: string; resHeaders: Record<string, string>; resBody: string
    reqRawHeaders: string[]; resRawHeaders: string[]
    reqLine: string; resLine: string
  }
}

const BODY_CAP = 1024 * 1024 // 明文 HTTP 请求体捕获上限

export class ProxyEngine {
  private server?: Server
  private upstream: Upstream = { type: 'direct' }
  private seq = 0
  onFlow?: (flow: FlowMeta) => void

  // ---- Intercept（请求拦截队列：http 明文请求 + CONNECT 隧道请求 + MITM 请求） ----
  interceptEnabled = false
  mitmEnabled = false
  interceptQueue: { id: number; kind: 'http' | 'connect' | 'mitm'; method: string; url: string; ts: number; req?: IncomingMessage; res?: ServerResponse; target?: URL; client?: Socket; head?: Buffer; resolve?: (allow: boolean) => void }[] = []
  private interceptSeq = 0
  onIntercept?: () => void

  async start(port: number, host = '127.0.0.1'): Promise<void> {
    this.server = createServer((req, res) => this.handleHttp(req, res))
    this.server.on('connect', (req, client, head) => this.handleConnect(req, client, head))
    this.server.on('error', (e) => console.error('[proxy] server error:', e))
    await new Promise<void>((resolve, reject) => {
      this.server!.once('error', reject)
      this.server!.listen(port, host, () => resolve())
    })
  }

  async stop(): Promise<void> {
    if (!this.server) return
    await new Promise<void>((resolve) => this.server!.close(() => resolve()))
    this.server = undefined
  }

  setUpstream(u: Upstream): void {
    this.upstream = u
  }

  getUpstream(): Upstream {
    return this.upstream
  }

  upstreamLabel(): string {
    const u = this.upstream
    if (u.type === 'direct') return 'direct'
    return `${u.type}://${u.host}:${u.port}`
  }

  /** 探测系统代理（Windows 注册表；无则 null）——浏览器默认走内置代理时保证出网 */
  detectSystemProxy(): Upstream | null {
    try {
      const key = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings'
      const en = execSync(`reg query "${key}" /v ProxyEnable`, { encoding: 'utf8', timeout: 3000 })
      if (!/0x1\b/i.test(en)) return null
      const srv = execSync(`reg query "${key}" /v ProxyServer`, { encoding: 'utf8', timeout: 3000 })
      const m = /REG_SZ\s+([^\r\n]+)/i.exec(srv)
      const proxy = m?.[1]?.trim()
      if (!proxy) return null
      const [host, port] = proxy.split(':')
      if (!host) return null
      return { type: 'http', host, port: Number(port) || 80 }
    } catch {
      return null
    }
  }

  private emit(f: Omit<FlowMeta, 'id'>): void {
    this.onFlow?.({ id: ++this.seq, ...f })
  }

  // ---------------- HTTP ----------------
  private handleHttp(req: IncomingMessage, res: ServerResponse): void {
    const target = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
    // Intercept：开关打开时挂起请求进入队列，等待放行/丢弃
    if (this.interceptEnabled) {
      const item = { id: ++this.interceptSeq, kind: 'http' as const, method: req.method ?? 'GET', url: target.href, ts: Date.now(), req, res, target }
      this.interceptQueue.push(item)
      this.onIntercept?.()
      return
    }
    this.forwardHttp(req, res, target)
  }

  /** 设置拦截开关；关闭时自动放行全部挂起请求（Burp 行为：关闭拦截不卡包） */
  setInterceptEnabled(v: boolean): void {
    this.interceptEnabled = v
    if (!v && this.interceptQueue.length) {
      const ids = this.interceptQueue.map((x) => x.id)
      for (const id of ids) this.forwardIntercepted(id)
    }
  }

  /** 放行拦截队列中的请求（继续转发） */
  forwardIntercepted(id: number): boolean {
    const i = this.interceptQueue.findIndex((x) => x.id === id)
    if (i < 0) return false
    const [item] = this.interceptQueue.splice(i, 1)
    if (item.kind === 'http' && item.req && item.res && item.target) {
      this.forwardHttp(item.req, item.res, item.target)
    } else if (item.kind === 'connect' && item.client) {
      const idx = (item.url ?? '').lastIndexOf(':')
      this.doConnect(item.url.slice(0, idx), parseInt(item.url.slice(idx + 1), 10) || 443, item.client, item.head)
    } else if (item.kind === 'mitm' && item.resolve) {
      item.resolve(true)
    }
    this.onIntercept?.()
    return true
  }

  /** 丢弃拦截队列中的请求 */
  dropIntercepted(id: number): boolean {
    const i = this.interceptQueue.findIndex((x) => x.id === id)
    if (i < 0) return false
    const [item] = this.interceptQueue.splice(i, 1)
    if (item.kind === 'http' && item.res) {
      item.res.writeHead(502, { 'content-type': 'text/plain' })
      item.res.end('intercepted & dropped')
    } else if (item.kind === 'connect' && item.client) {
      item.client.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
      item.client.destroy()
    } else if (item.kind === 'mitm' && item.resolve) {
      item.resolve(false)
    }
    this.emit({ ts: item.ts, kind: item.kind, method: item.method, url: item.url, status: 0, bytes: 0, upstream: this.upstreamLabel(), error: 'dropped by intercept' })
    this.onIntercept?.()
    return true
  }

  private forwardHttp(req: IncomingMessage, res: ServerResponse, target: URL): void {
    const start = Date.now()
    const upstreamIsTls = this.upstream.type === 'https'
    const doReq = upstreamIsTls ? httpsRequest : httpRequest

    // ponytail: 明文 HTTP 请求体做有限捕获，HTTPS 内容交给浏览器侧（CDP Network / Firefox 代理会话）
    let reqBody = ''
    let bytes = 0
    if (req.headers['content-type']?.includes('application/json') || req.method === 'POST') {
      req.on('data', (c) => { bytes += c.length; if (reqBody.length < BODY_CAP) reqBody += c })
    }

    const options = {
      protocol: upstreamIsTls ? 'https:' : 'http:',
      hostname: target.hostname,
      port: target.port || (upstreamIsTls ? 443 : 80),
      path: target.pathname + target.search,
      method: req.method,
      headers: { ...req.headers },
      agent: this.upstreamAgent(),
    }
    delete (options.headers as Record<string, string>)['proxy-connection']

    const up = doReq(options, (upRes) => {
      res.writeHead(upRes.statusCode ?? 502, upRes.headers)
      const resChunks: Buffer[] = []
      let resLen = 0
      upRes.on('data', (c) => { bytes += c.length; resLen += c.length; if (resLen <= BODY_CAP) resChunks.push(c) })
      upRes.pipe(res)
      upRes.on('end', () => {
        const rawLines = (arr: string[]) => { const l: string[] = []; for (let i = 0; i + 1 < arr.length; i += 2) l.push(`${arr[i]}: ${arr[i + 1]}`); return l }
        this.emit({
          ts: start, method: req.method ?? 'GET', url: target.href, status: upRes.statusCode ?? 0, bytes, upstream: this.upstreamLabel(),
          detail: {
            reqHeaders: req.headers as Record<string, string>, reqBody, reqRawHeaders: rawLines(req.rawHeaders), reqLine: `${req.method ?? 'GET'} ${req.url} HTTP/${req.httpVersion}`,
            resHeaders: upRes.headers as Record<string, string>, resBody: resChunks.length ? decodeBody(Buffer.concat(resChunks), (upRes.headers['content-encoding'] as string) || undefined) : '', resRawHeaders: rawLines(upRes.rawHeaders), resLine: `HTTP/${upRes.httpVersion} ${upRes.statusCode} ${upRes.statusMessage ?? ''}`,
          },
        })
      })
    })
    up.on('error', (e) => {
      res.writeHead(502, { 'content-type': 'text/plain' })
      res.end(`proxy error: ${e.message}`)
      this.emit({ ts: start, method: req.method ?? 'GET', url: target.href, status: 502, bytes, upstream: this.upstreamLabel(), error: e.message })
    })
    req.pipe(up)
  }

  private upstreamAgent(): SocksProxyAgent | HttpProxyAgent | undefined {
    const u = this.upstream
    if (u.type === 'direct') return undefined
    if (u.type === 'socks4' || u.type === 'socks5' || u.type === 'socks5h') {
      return new SocksProxyAgent({
        hostname: u.host, port: u.port, username: u.username, password: u.password,
        type: u.type === 'socks4' ? 4 : 5,
      })
    }
    return new HttpProxyAgent({ hostname: u.host, port: u.port, protocol: u.type, username: u.username, password: u.password })
  }

  // ---------------- CONNECT（HTTPS / 任意 TCP 隧道） ----------------
  private handleConnect(req: IncomingMessage, client: Socket, head: Buffer): void {
    const idx = (req.url ?? '').lastIndexOf(':')
    const host = (req.url ?? '').slice(0, idx)
    const port = parseInt((req.url ?? '').slice(idx + 1), 10) || 443
    // Intercept：开关打开时挂起隧道请求（HTTPS 流量也可见；MITM 开启时由明文层拦截，CONNECT 直通）
    if (this.interceptEnabled && !this.mitmEnabled) {
      const item = { id: ++this.interceptSeq, kind: 'connect' as const, method: 'CONNECT', url: `${host}:${port}`, ts: Date.now(), client, head }
      this.interceptQueue.push(item)
      this.onIntercept?.()
      return
    }
    this.doConnect(host, port, client, head)
  }

  private doConnect(host: string, port: number, client: Socket, head?: Buffer): void {
    const start = Date.now()
    let bytes = 0

    // MITM：开关打开时 TLS 终止 + 明文捕获/拦截（客户端需信任 CA 或 --ignore-certificate-errors）
    if (this.mitmEnabled) {
      const tunnels = new Set<{ close: () => void }>()
      // ponytail: 单布尔标记区分重发器流（并发重发极罕见，串行用户操作足够）；per-connection 标记需改 mitm.ts 回调签名
      let repeaterFlow = false
      const t = mitmTunnel(client, host, head ?? Buffer.alloc(0), this.upstream, {
        onRequest: async (info) => {
          // 重发器标记头：转发但流量不进应用流量表
          if (info.headers['x-pentbox-source'] === 'repeater') { repeaterFlow = true; return true }
          if (!this.interceptEnabled) return true
          return await new Promise<boolean>((resolve) => {
            const item = { id: ++this.interceptSeq, kind: 'mitm' as const, method: info.method, url: info.url, ts: Date.now(), resolve }
            this.interceptQueue.push(item)
            this.onIntercept?.()
          })
        },
        onFlow: (f) => {
          if (repeaterFlow) { repeaterFlow = false; return }  // 重发器流量跳过记录/审计
          this.emit(f)
        },
      })
      tunnels.add(t)
      client.on('close', () => t.close())
      return
    }

    this.connectUpstream(host, port)
      .then((up) => {
        client.write('HTTP/1.1 200 Connection Established\r\n\r\n')
        if (head?.length) up.write(head)
        up.on('data', (c) => (bytes += c.length))
        up.pipe(client)
        client.pipe(up)
        up.on('close', () => this.emit({ ts: start, method: 'CONNECT', url: `${host}:${port}`, status: 200, bytes, upstream: this.upstreamLabel() }))
      })
      .catch((e: Error) => {
        client.end('HTTP/1.1 502 Bad Gateway\r\n\r\n')
        this.emit({ ts: start, method: 'CONNECT', url: `${host}:${port}`, status: 502, bytes: 0, upstream: this.upstreamLabel(), error: e.message })
      })
  }

  private connectUpstream(host: string, port: number): Promise<Socket> {
    const u = this.upstream
    if (u.type === 'direct') {
      return new Promise((resolve, reject) => {
        const s = netConnect(port, host)
        s.once('connect', () => resolve(s))
        s.once('error', reject)
      })
    }
    if (u.type === 'socks4' || u.type === 'socks5' || u.type === 'socks5h') {
      return SocksClient.createConnection({
        proxy: {
          host: u.host, port: u.port, type: u.type === 'socks4' ? 4 : 5,
          userId: u.username, password: u.password,
        },
        command: 'connect',
        destination: { host, port },
      }).then((info) => info.socket)
    }
    // http(s) 上游：向上游发 CONNECT
    const doReq = u.type === 'https' ? httpsRequest : httpRequest
    return new Promise((resolve, reject) => {
      const auth = u.username ? `Proxy-Authorization: Basic ${Buffer.from(`${u.username}:${u.password ?? ''}`).toString('base64')}` : ''
      const req = doReq({
        host: u.host, port: u.port, method: 'CONNECT', path: `${host}:${port}`,
        headers: { host: `${host}:${port}`, ...(auth ? { 'proxy-authorization': auth } : {}) },
      })
      req.once('connect', (res, socket) => resolve(socket))
      req.once('error', reject)
      req.end()
    })
  }
}
