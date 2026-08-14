/**
 * HTTPS MITM：自签 CA + 动态签发目标证书 + TLS 终止 + 明文 HTTP 转发
 * 客户端需信任 CA（浏览器可 --ignore-certificate-errors 快速验证）
 */
import tls from 'node:tls'
import { Socket } from 'node:net'
import forge from 'node-forge'
import fs from 'node:fs'
import path from 'node:path'
import os from 'node:os'
import zlib from 'node:zlib'
import { createServer, request as httpRequestProxy, type IncomingMessage, type ServerResponse } from 'node:http'
import { request as httpsRequestTls } from 'node:https'
import { HttpsProxyAgent } from 'https-proxy-agent'
import { SocksProxyAgent } from 'socks-proxy-agent'
import type { Downstream, Upstream } from './proxy.ts'

export interface MitmCallbacks {
  /** 明文请求到达（拦截点）：返回 true 放行转发，false 丢弃 */
  onRequest?: (info: { id: number; method: string; url: string; headers: Record<string, string>; body: string }) => Promise<boolean> | boolean
  onFlow?: (f: {
    ts: number; method: string; url: string; status: number; bytes: number; upstream: string
    /** 渗透目标流量标记（代理层 setPenetrateTarget 命中） */
    self?: boolean
    detail?: {
      reqHeaders: Record<string, string>; reqBody: string; resHeaders: Record<string, string>; resBody: string
      /** 原始头行（保留大小写/顺序/重复头，如 Set-Cookie 每行一条） */
      reqRawHeaders: string[]; resRawHeaders: string[]
      /** 状态行（BP 风格首行）：HTTP/1.1 200 OK */
      reqLine: string; resLine: string
    }
  }) => void
}

const CERT_DIR = path.join(os.homedir(), '.pentbox')
const CA_KEY = path.join(CERT_DIR, 'pentbox-ca.key')
const CA_CRT = path.join(CERT_DIR, 'pentbox-ca.crt')

let caKey: forge.pki.PrivateKey | null = null
let caCert: forge.pki.Certificate | null = null
let caPemKey = ''
let caPemCert = ''

function ensureCA(): void {
  if (caKey && caCert) return
  fs.mkdirSync(CERT_DIR, { recursive: true })
  if (fs.existsSync(CA_KEY) && fs.existsSync(CA_CRT)) {
    try {
      caPemKey = fs.readFileSync(CA_KEY, 'utf8')
      caPemCert = fs.readFileSync(CA_CRT, 'utf8')
      caKey = forge.pki.privateKeyFromPem(caPemKey)
      caCert = forge.pki.certificateFromPem(caPemCert)
      return
    } catch { /* 损坏则重建 */ }
  }
  const keys = forge.pki.rsa.generateKeyPair(2048)
  const cert = forge.pki.createCertificate()
  cert.publicKey = keys.publicKey
  cert.serialNumber = '01' + Date.now().toString(16)
  cert.validity.notBefore = new Date(Date.now() - 86400000)
  cert.validity.notAfter = new Date(Date.now() + 3650 * 86400000)
  const attrs = [{ name: 'commonName', value: 'PentBox MITM Root CA' }, { name: 'organizationName', value: 'PentBox' }]
  cert.setSubject(attrs)
  cert.setIssuer(attrs)
  cert.setExtensions([{ name: 'basicConstraints', cA: true }, { name: 'keyUsage', keyCertSign: true, digitalSignature: true }, { name: 'subjectKeyIdentifier' }])
  cert.sign(keys.privateKey, forge.md.sha256.create())
  caPemKey = forge.pki.privateKeyToPem(keys.privateKey)
  caPemCert = forge.pki.certificateToPem(cert)
  fs.writeFileSync(CA_KEY, caPemKey)
  fs.writeFileSync(CA_CRT, caPemCert)
  caKey = keys.privateKey
  caCert = cert
}

export function getCaCertPath(): string {
  ensureCA()
  return CA_CRT
}

export function getCaCertPem(): string {
  ensureCA()
  return caPemCert
}

/** 检测系统是否已信任 PentBox CA（certutil 当前用户 Root 库，无需管理员） */
export function isCaTrusted(): boolean {
  try {
    const { execSync } = require('node:child_process') as typeof import('node:child_process')
    const out = execSync('certutil -user -store Root "PentBox MITM Root CA"', { encoding: 'utf8', timeout: 5000, stdio: ['ignore', 'pipe', 'ignore'] })
    return /PentBox MITM Root CA/i.test(out)
  } catch {
    return false
  }
}

/** 一键安装 CA 到当前用户受信任根库（certutil -user 无需管理员） */
export function installCa(): { ok: boolean; error?: string } {
  try {
    ensureCA()
    const { execSync } = require('node:child_process') as typeof import('node:child_process')
    execSync(`certutil -user -addstore -f Root "${CA_CRT}"`, { encoding: 'utf8', timeout: 15000, stdio: ['ignore', 'pipe', 'ignore'] })
    return { ok: isCaTrusted() }
  } catch (e) {
    return { ok: false, error: (e as Error).message }
  }
}

/** MITM 上游转发代理（直连/HTTP/SOCKS 与代理引擎同链）；本地地址与 direct 返回 undefined 走直连 */
function upstreamAgent(up: Upstream): HttpsProxyAgent<string> | SocksProxyAgent | undefined {
  // 本地/内网地址不走上游（v2ray 等不转发 localhost）；direct 无 host/port
  const host = 'host' in up ? up.host : ''
  const port = 'port' in up ? up.port : 0
  if (/^(localhost|127\.\d+\.\d+\.\d+|\[?::1\]?|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+)$/.test(host)) return undefined
  if (up.type === 'http') return new HttpsProxyAgent(`http://${host}:${port}`)
  if (up.type === 'socks4' || up.type === 'socks5' || up.type === 'socks5h') {
    const auth = up.username ? `${up.username}:${up.password ?? ''}@` : ''
    return new SocksProxyAgent(`${up.type === 'socks5h' ? 'socks5h' : up.type}://${auth}${host}:${port}`)
  }
  return undefined
}

/** 类 Burp：向下游代理建 CONNECT 隧道，在隧道内做 TLS 二次握手（MITM 解密后仍经下游到达目标） */
function connectViaDownstream(ds: Downstream, host: string, port: number): Promise<tls.TLSSocket> {
  return new Promise((resolve, reject) => {
    const req = httpRequestProxy({
      host: ds.host, port: ds.port, method: 'CONNECT', path: `${host}:${port}`,
      headers: { host: `${host}:${port}` },
    })
    req.once('connect', (res, socket) => {
      const ts = tls.connect({ socket, servername: host, rejectUnauthorized: false })
      ts.once('secureConnect', () => resolve(ts))
      ts.once('error', reject)
    })
    req.once('error', reject)
    req.end()
  })
}

/** 扁平 rawHeaders 转原始头行数组（保留大小写/顺序/重复头） */
function rawToLines(raw: string[]): string[] {
  const lines: string[] = []
  for (let i = 0; i + 1 < raw.length; i += 2) lines.push(`${raw[i]}: ${raw[i + 1]}`)
  return lines
}

/** 按 Content-Encoding 解压响应/请求体（cap 内同步解压；失败返回原文） */
export function decodeBody(buf: Buffer, encoding: string | undefined, cap = 262144): string {
  try {
    let out: Buffer
    if (encoding === 'gzip') out = zlib.gunzipSync(buf)
    else if (encoding === 'deflate') out = zlib.inflateSync(buf)
    else if (encoding === 'br') out = zlib.brotliDecompressSync(buf)
    else return buf.toString('utf8').slice(0, cap)
    return out.toString('utf8').slice(0, cap)
  } catch {
    return buf.toString('utf8').slice(0, cap)
  }
}

/** 为目标域名签发短期证书（内存缓存） */
const certCache = new Map<string, { key: string; cert: string }>()
function signForHost(host: string): { key: string; cert: string } {
  ensureCA()
  const cached = certCache.get(host)
  if (cached) return cached
  const keys = forge.pki.rsa.generateKeyPair(2048)
  const cert = forge.pki.createCertificate()
  cert.publicKey = keys.publicKey
  cert.serialNumber = '02' + Math.floor(Math.random() * 1e12).toString(16)
  cert.validity.notBefore = new Date(Date.now() - 3600000)
  cert.validity.notAfter = new Date(Date.now() + 30 * 86400000)
  cert.setSubject([{ name: 'commonName', value: host }])
  cert.setIssuer(caCert!.subject.attributes)
  const altNames = []
  const isIp = /^(\d+\.\d+\.\d+\.\d+|\[?[0-9a-fA-F:]+\]?)$/.test(host)
  if (isIp) {
    altNames.push({ type: 7, ip: host.replace(/^\[|\]$/g, '') })
  } else {
    altNames.push({ type: 2, value: host })
    // 本地主机名补 IPv4 SAN（node-forge 的 IP SAN 必须用 ip 字段，value 会生成畸形扩展）
    if (host === 'localhost') altNames.push({ type: 7, ip: '127.0.0.1' })
  }
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
    { name: 'extKeyUsage', serverAuth: true },
    { name: 'subjectAltName', altNames },
  ])
  cert.sign(caKey! as forge.pki.rsa.PrivateKey, forge.md.sha256.create())
  const out = { key: forge.pki.privateKeyToPem(keys.privateKey), cert: forge.pki.certificateToPem(cert) + caPemCert }
  certCache.set(host, out)
  return out
}

export interface MitmTunnel {
  close: () => void
}

/**
 * 在 CONNECT 隧道内做 TLS 终止：client(明文) → TLS → 转发到目标(https)
 * @param client 已连上代理的客户端 socket（代理已回 200 Connection Established）
 * @param host 目标主机
 * @param head CONNECT 后客户端可能立即发来的 TLS 握手字节
 * @param upstream 当前上游配置（仅用于打标签）
 * @param cb 回调（onRequest 返回 false 时请求被丢弃）
 */
export function mitmTunnel(client: Socket, host: string, head: Buffer, upstream: Upstream, downstream: Downstream | null, cb: MitmCallbacks): MitmTunnel {
  let key: string, cert: string
  try {
    const c = signForHost(host)
    key = c.key
    cert = c.cert
  } catch (e) {
    console.error('[mitm] signForHost failed:', host, (e as Error).message)
    client.destroy()
    throw e
  }
  const ctx = tls.createSecureContext({ key, cert })
  // 先回 200，再 head 回流，再包 TLSSocket（服务端模式）
  client.write('HTTP/1.1 200 Connection Established\r\n\r\n')
  if (head.length) client.unshift(head)
  const tlsSock = new tls.TLSSocket(client, { isServer: true, secureContext: ctx })
  tlsSock.on('error', () => {})
  let detached = false

  async function handleHttpReq(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const target = new URL(req.url ?? '/', `http://${req.headers.host ?? host}`)
    // 隧道是 HTTPS 的：流量记录用原始 https:// URL（否则出现 http/https 双记录）
    const flowUrl = `https://${target.host}${target.pathname + target.search}`
    // 全量捕获请求体（cap 256KB，Buffer 收集，输出时按编码解压）
    const reqChunks: Buffer[] = []
    let reqLen = 0
    let bytes = 0
    req.on('data', (c: Buffer) => { bytes += c.length; if (reqLen < 262144) { reqChunks.push(c); reqLen += c.length } })
    // 拦截点（挂起期间暂停请求流，避免 body 被消费丢失；放行后恢复）
    if (cb.onRequest) {
      req.pause()
      const allow = await cb.onRequest({
        id: Math.floor(Math.random() * 1e9),
        method: req.method ?? 'GET',
        url: flowUrl,
        headers: req.headers as Record<string, string>,
        body: decodeBody(Buffer.concat(reqChunks), (req.headers['content-encoding'] as string) || undefined),
      })
      req.resume()
      if (!allow) {
        res.writeHead(502, { 'content-type': 'text/plain' })
        res.end('intercepted & dropped')
        return
      }
    }
    const start = Date.now()
    const ds = downstream
    const opts: any = {
      hostname: target.hostname,
      port: Number(target.port || 443),
      path: target.pathname + target.search,
      method: req.method,
      headers: { ...req.headers } as Record<string, string>,
      rejectUnauthorized: false,
      // 类 Burp：设置了下游代理则出口经下游（CONNECT 隧道内做 TLS 二次握手），否则走原上游链
      agent: ds ? undefined : upstreamAgent(upstream),
      ...(ds ? { createConnection: () => connectViaDownstream(ds, target.hostname, Number(target.port || 443)) } : {}),
    }
    delete opts.headers['proxy-connection']
    // 内部标记头（WebShell/Repeater）不转发到目标，避免暴露工具特征
    delete opts.headers['x-pentbox-source']
    const up = httpsRequestTls(opts, (upRes) => {
      // 全量捕获响应体（cap 256KB）；响应结束才发 flow（body 快照完整 + 按编码解压）
      const resChunks: Buffer[] = []
      let resLen = 0
      upRes.on('data', (c: Buffer) => { bytes += c.length; if (resLen < 262144) { resChunks.push(c); resLen += c.length } })
      res.writeHead(upRes.statusCode ?? 502, upRes.headers)
      upRes.pipe(res)
      upRes.on('end', () => {
        const enc = (upRes.headers['content-encoding'] as string) || undefined
        cb.onFlow?.({
          ts: start, method: req.method ?? 'GET', url: flowUrl, status: upRes.statusCode ?? 0, bytes, upstream: ds ? `downstream:${ds.protocol || 'http'}://${ds.host}:${ds.port}` : upstream.type === 'direct' ? 'direct' : `${upstream.type}://${upstream.host}:${upstream.port}`,
          detail: {
            reqHeaders: req.headers as Record<string, string>,
            reqBody: decodeBody(Buffer.concat(reqChunks), (req.headers['content-encoding'] as string) || undefined),
            resHeaders: upRes.headers as Record<string, string>,
            resBody: decodeBody(Buffer.concat(resChunks), enc),
            // 原始头行（保留原始大小写/顺序/重复头，BP 风格逐行显示）+ 状态行
            reqRawHeaders: rawToLines(req.rawHeaders),
            resRawHeaders: rawToLines(upRes.rawHeaders),
            reqLine: `${req.method ?? 'GET'} ${target.pathname + target.search} HTTP/${req.httpVersion}`,
            resLine: `HTTP/${upRes.httpVersion} ${upRes.statusCode ?? 0} ${upRes.statusMessage ?? ''}`,
          },
        })
      })
    })
    up.on('error', (e: Error) => {
      res.writeHead(502, { 'content-type': 'text/plain' })
      res.end(`mitm error: ${e.message}`)
      cb.onFlow?.({
        ts: start, method: req.method ?? 'GET', url: flowUrl, status: 502, bytes: 0, upstream: ds ? `downstream:${ds.protocol || 'http'}://${ds.host}:${ds.port}` : upstream.type === 'direct' ? 'direct' : `${upstream.type}://${'host' in upstream ? upstream.host : ''}:${'port' in upstream ? upstream.port : 0}`,
        detail: { reqHeaders: req.headers as Record<string, string>, reqBody: decodeBody(Buffer.concat(reqChunks), (req.headers['content-encoding'] as string) || undefined), resHeaders: {}, resBody: '', reqRawHeaders: [], resRawHeaders: [], reqLine: `${req.method ?? 'GET'} ${target.pathname + target.search} HTTP/${req.httpVersion}`, resLine: 'HTTP/1.1 502 Bad Gateway' },
      })
    })
    req.pipe(up)
  }

  tlsSock.on('error', (e) => {
    // BAD_PACKET_LENGTH = 客户端往 TLS 端口发非 TLS 数据（端口探测/乱数据），纯噪声不打印；其余握手错误保留
    if (e.message.includes('BAD_PACKET_LENGTH')) return
    console.error('[mitm] tls handshake:', e.message)
  })
  // 服务端 TLSSocket 握手完成触发 'secure'（'secureConnect' 是客户端事件）
  tlsSock.on('secure', () => {
    if (detached) return
    const server = createServer((req, res) => { void handleHttpReq(req, res) })
    server.on('error', () => {})
    server.emit('connection', tlsSock)
  })

  return { close: () => tlsSock.destroy() }
}
