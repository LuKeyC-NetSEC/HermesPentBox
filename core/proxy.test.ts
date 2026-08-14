/**
 * 代理引擎全链路自测（全本地，无外网依赖）
 * 链路: curl -x 主引擎:8899 → [上游:8900] → 目标:8800 / echo:8801
 * 验证: HTTP 直连 / HTTP 经上游 / CONNECT 直连 / CONNECT 经上游 / onFlow 记录
 */
import assert from 'node:assert/strict'
import { createServer, request } from 'node:http'
import { createServer as createNetServer, connect } from 'node:net'
import { spawn } from 'node:child_process'
import { ProxyEngine } from './proxy.ts'
import type { FlowMeta } from './proxy.ts'

const flows: FlowMeta[] = []
const record = [] as any[]

function listen(srv: any, port: number): Promise<void> {
  return new Promise((resolve, reject) => {
    srv.once('error', reject)
    srv.listen(port, '127.0.0.1', resolve)
  })
}

// ---- 1. 目标 HTTP server :8800 ----
const target = createServer((req, res) => {
  let body = ''
  req.on('data', (c) => (body += c))
  req.on('end', () => res.end(`hello ${req.method} ${req.url} body=${body}`))
})
await listen(target, 8800)

// ---- 2. echo TCP server :8801（CONNECT 隧道目标） ----
const echo = createNetServer((s) => s.pipe(s))
await listen(echo, 8801)

// ---- 3. 上游 HTTP 代理 :8900 ----
const upstream = createServer((req, res) => {
  const u = new URL(req.url ?? '/', `http://${req.headers.host ?? 'localhost'}`)
  const p = request(
    { hostname: u.hostname, port: Number(u.port) || 80, path: u.pathname + u.search, method: req.method, headers: req.headers },
    (r) => { res.writeHead(r.statusCode ?? 502, r.headers); r.pipe(res) },
  )
  p.on('error', (e) => { res.writeHead(502); res.end(String(e)) })
  req.pipe(p)
})
upstream.on('connect', (req, client, head) => {
  const [h, p] = (req.url ?? '').split(':')
  const s = connect(Number(p), h)
  s.once('connect', () => {
    client.write('HTTP/1.1 200 Connection Established\r\n\r\n')
    if (head.length) s.write(head)
    s.pipe(client); client.pipe(s)
  })
  s.once('error', () => client.end())
})
await listen(upstream, 8900)

// ---- 4. 主引擎 :8899 ----
const engine = new ProxyEngine()
engine.onFlow = (f) => { flows.push(f); record.push(f) }
await engine.start(8899)

function curl(args: string[]): Promise<void> {
  return new Promise((resolve, reject) => {
    // ponytail: Windows 下 curl 的 stdout/stderr 为 pipe 时会卡死（进度条块缓冲），必须 inherit
    const c = spawn('curl', ['-s', '-f', '-m', '8', '-x', 'http://127.0.0.1:8899', ...args], { stdio: 'inherit' })
    c.on('close', (code) => (code === 0 ? resolve() : reject(new Error(`curl exit ${code}`))))
  })
}

// ---- 自检：node 同进程直连（debug.ts 验证过的路径） ----
const probe = await new Promise<string>((resolve) => {
  const r = request({ host: '127.0.0.1', port: 8899, method: 'GET', path: 'http://127.0.0.1:8800/probe', headers: { host: '127.0.0.1:8800' } }, (res) => {
    let b = ''
    res.on('data', (d) => (b += d))
    res.on('end', () => resolve(`node-probe:${res.statusCode}:${b}`))
  })
  r.on('error', (e) => resolve(`node-probe-ERR:${e.message}`))
  r.end()
})
console.log('[probe]', probe)

// ---- 端口归属检查 ----
await new Promise<void>((resolve) => {
  const ns = spawn('netstat', ['-ano'], { stdio: ['ignore', 'pipe', 'pipe'] })
  let out = ''
  ns.stdout.on('data', (d) => (out += d))
  ns.on('close', () => {
    console.log('[netstat-8899]', out.split('\n').filter((l) => l.includes(':8899') || l.includes(':8800')).join(' | '))
    console.log('[test-pid]', process.pid)
    resolve()
  })
})

// ---- 硬编码 curl 直出 ----（stdio inherit 已由 helper 承担，移除）

// CONNECT 隧道客户端（真实客户端行为：发 CONNECT → 隧道 → 发数据 → 收回显）
function tunnelEcho(host: string, port: number, payload: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = connect(8899, '127.0.0.1')
    let buf = ''
    let tunneled = false
    const timer = setTimeout(() => { s.destroy(); reject(new Error('tunnel timeout')) }, 5000)
    s.on('connect', () => s.write(`CONNECT ${host}:${port} HTTP/1.1\r\nHost: ${host}:${port}\r\n\r\n`))
    s.on('data', (d) => {
      buf += d.toString()
      if (!tunneled) {
        const idx = buf.indexOf('\r\n\r\n')
        if (idx < 0) return
        const head = buf.slice(0, idx)
        if (!head.includes('200')) { clearTimeout(timer); s.destroy(); reject(new Error('CONNECT failed: ' + head)); return }
        tunneled = true
        buf = buf.slice(idx + 4)
        s.write(payload)
      }
      if (tunneled && buf.includes(payload)) {
        clearTimeout(timer); s.end(); resolve(buf)
      }
    })
    s.on('error', (e) => { clearTimeout(timer); reject(e) })
  })
}

// ---- T1: HTTP 直连 ----
await curl(['http://127.0.0.1:8800/hello'])

// ---- T2: POST JSON ----
await curl(['-H', 'content-type: application/json', '-d', '{"a":1}', 'http://127.0.0.1:8800/post'])

// ---- T3: CONNECT 直连（隧道 → echo） ----
const t3 = await tunnelEcho('127.0.0.1', 8801, 'PING')
assert.ok(t3.includes('PING'), `T3: ${t3}`)

// ---- T4: 切到 http 上游后重跑 HTTP + CONNECT ----
engine.setUpstream({ type: 'http', host: '127.0.0.1', port: 8900 })
await curl(['http://127.0.0.1:8800/upstream'])
const t4b = await tunnelEcho('127.0.0.1', 8801, 'PING2')
assert.ok(t4b.includes('PING2'), `T4b: ${t4b}`)

// ---- T5: onFlow 记录（等隧道 close 事件落定） ----
await new Promise<void>((r) => setTimeout(r, 300))
assert.ok(flows.length >= 4, `flows=${flows.length}`)
const httpFlow = flows.find((f) => f.url.includes('/hello'))
assert.ok(httpFlow && httpFlow.method === 'GET' && httpFlow.status === 200 && httpFlow.upstream === 'direct')
const upFlow = flows.find((f) => f.url.includes('/upstream'))
assert.ok(upFlow && upFlow.upstream === 'http://127.0.0.1:8900', 'upstream 标签正确')
const conFlow = flows.find((f) => f.method === 'CONNECT' && f.url.includes('8801'))
assert.ok(conFlow && conFlow.status === 200, 'CONNECT 记录正确')

console.log('flows:')
for (const f of flows) console.log(`  #${f.id} ${f.method} ${f.url} -> ${f.status} ${f.bytes}B [${f.upstream}]${f.error ? ' ERR:' + f.error : ''}`)
console.log('\nALL PASS ✓')
process.exit(0)
