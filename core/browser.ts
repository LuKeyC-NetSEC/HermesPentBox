/**
 * Chrome 浏览器控制（CDP）
 * - launch: 工作台拉起专用 Chrome（可指向上游代理 + 独立 profile）
 * - attach: 连接已运行的 Chrome（--remote-debugging-port=9222）
 * - Network 事件 → 流量捕获（含 HTTPS 明文，比代理层更全）
 */
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import CDP from 'chrome-remote-interface'

export interface WebFlow {
  id: number
  ts: number
  method: string
  url: string
  status: number
  bytes: number
  source: 'browser'
  requestId?: string
  postData?: string
}

export interface ChromeOptions {
  port?: number          // CDP 调试端口（launch/attach 共用）
  proxyPort?: number     // launch 时浏览器代理指向内置代理引擎
  customProxy?: string   // 自定义代理 host:port（如 Burp 127.0.0.1:8889），优先于 proxyPort
  userDataDir?: string   // launch 时专用 profile（默认临时目录）
  headless?: boolean
}

export function chromeExecutable(): string {
  const env = process.env.CHROME_PATH
  if (env && existsSync(env)) return env
  const candidates =
    process.platform === 'win32'
      ? [
          'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
          'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
          join(process.env.LOCALAPPDATA ?? '', 'Google\\Chrome\\Application\\chrome.exe'),
        ]
      : ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser']
  const hit = candidates.find((p) => existsSync(p))
  if (!hit) throw new Error('Chrome not found, set CHROME_PATH')
  return hit
}

export class ChromeBrowser {
  private proc?: ChildProcess
  private client?: CDP.Client
  private seq = 0
  private pending = new Map<string, { method: string; url: string; status: number; bytes: number; ts: number; postData?: string }>()
  private debugPort = 9222
  private userDataDir?: string
  onFlow?: (f: WebFlow) => void
  onWsFrame?: (f: { ts: number; direction: 'sent' | 'received'; payload: string; length: number }) => void

  /** 拉起专用 Chrome（--proxy-server 指向内置代理） */
  async launch(opts: ChromeOptions = {}): Promise<void> {
    this.debugPort = opts.port ?? 9222
    this.userDataDir = opts.userDataDir ?? join(tmpdir(), `pentbox-chrome-${Date.now()}`)
    const proxyArg = opts.customProxy
      ? `--proxy-server=http://${opts.customProxy}`
      : `--proxy-server=http://127.0.0.1:${opts.proxyPort ?? 8899}`
    // 浏览器 launch：CA 已受信任则走真证书校验（正规 CA 流程），否则带 --ignore-certificate-errors 保可用
    const { isCaTrusted } = await import('../core/mitm.ts')
    const args = [
      `--remote-debugging-port=${this.debugPort}`,
      `--user-data-dir=${this.userDataDir}`,
      '--no-first-run',
      '--no-default-browser-check',
      '--disable-background-networking',
      '--disable-component-update',
      '--proxy-bypass-list=<-loopback>',
      ...(isCaTrusted() ? [] : ['--ignore-certificate-errors']),
      ...(proxyArg ? [proxyArg] : []),
      ...(opts.headless ? ['--headless=new'] : []),
      'about:blank',
    ]
    this.proc = spawn(chromeExecutable(), args, { stdio: 'ignore' })
    this.proc.on('exit', () => { this.proc = undefined })
    await this.waitReady()
    await this.connect()
  }

  /** 连接已运行的 Chrome（用户日常实例） */
  async attach(port = 9222): Promise<void> {
    this.debugPort = port
    await this.connect()
  }

  private async waitReady(): Promise<void> {
    const deadline = Date.now() + 15000
    while (Date.now() < deadline) {
      try {
        const r = await fetch(`http://127.0.0.1:${this.debugPort}/json/version`)
        if (r.ok) return
      } catch { /* 未就绪 */ }
      await new Promise((r) => setTimeout(r, 200))
    }
    throw new Error(`Chrome CDP not ready on ${this.debugPort}`)
  }

  private async connect(): Promise<void> {
    this.client = await CDP({ port: this.debugPort })
    const { Network, Page } = this.client
    await Network.enable()
    await Page.enable()
    // 注意：chrome-remote-interface 0.34 事件回调签名是 (params, sessionId)，不是 ({params})
    Network.requestWillBeSent((params) => {
      if (params.type !== 'Document' && params.type !== 'XHR' && params.type !== 'Fetch' && params.type !== 'Script' && params.type !== 'Stylesheet' && params.type !== 'Image') return
      this.pending.set(params.requestId, {
        method: params.request.method,
        url: params.request.url,
        status: 0,
        bytes: 0,
        ts: Date.now(),
        postData: params.request.postData,
      })
    })
    Network.responseReceived((params) => {
      const p = this.pending.get(params.requestId)
      if (p) p.status = params.response.status
    })
    Network.loadingFinished((params) => {
      const p = this.pending.get(params.requestId)
      if (!p) return
      this.pending.delete(params.requestId)
      this.onFlow?.({ id: 1000000 + ++this.seq, ts: p.ts, method: p.method, url: p.url, status: p.status, bytes: params.encodedDataLength ?? p.bytes, source: 'browser', requestId: params.requestId, postData: p.postData })
    })
    Network.loadingFailed((params) => {
      const p = this.pending.get(params.requestId)
      if (!p) return
      this.pending.delete(params.requestId)
      this.onFlow?.({ id: 1000000 + ++this.seq, ts: p.ts, method: p.method, url: p.url, status: 0, bytes: 0, source: 'browser', requestId: params.requestId })
    })
    // WebSocket 帧捕获（WS History：TLS 隧道内代理看不到明文，CDP 可直接拿帧）
    Network.webSocketFrameSent((params) => {
      this.onWsFrame?.({ ts: Date.now(), direction: 'sent', payload: params.response?.payloadData ?? '', length: params.response?.payloadData?.length ?? 0 })
    })
    Network.webSocketFrameReceived((params) => {
      this.onWsFrame?.({ ts: Date.now(), direction: 'received', payload: params.response?.payloadData ?? '', length: params.response?.payloadData?.length ?? 0 })
    })
  }

  isRunning(): boolean {
    return !!this.client
  }

  async navigate(url: string): Promise<void> {
    const { Page } = this.client!
    await Page.navigate({ url })
  }

  async evaluate(expression: string): Promise<unknown> {
    const { Runtime } = this.client!
    const r = await Runtime.evaluate({ expression, returnByValue: true })
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.text ?? 'eval exception')
    return r.result.value
  }

  /** 懒取响应体（请求体在 postData 已带） */
  async getResponseBody(requestId: string): Promise<{ body: string; base64Encoded: boolean }> {
    const { Network } = this.client!
    const r = await Network.getResponseBody({ requestId })
    return { body: r.body, base64Encoded: r.base64Encoded }
  }

  async screenshot(): Promise<Buffer> {
    const { Page } = this.client!
    const r = await Page.captureScreenshot({ format: 'png' })
    return Buffer.from(r.data, 'base64')
  }

  async stop(): Promise<void> {
    try { await this.client?.close() } catch { /* 已断开 */ }
    this.client = undefined
    if (this.proc) {
      this.proc.kill()
      this.proc = undefined
    }
  }
}
