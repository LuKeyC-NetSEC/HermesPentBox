/**
 * API 层自测：status / upstream 设置 / flows 查询 / 增量 after / SSE 实时事件
 */
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { get as httpGet } from 'node:http'
import { ProxyEngine } from './proxy.ts'
import { ApiServer } from './api.ts'

const BASE = 'http://127.0.0.1:8877'
const target = createServer((q, s) => s.end('api-ok'))
await new Promise<void>((r) => target.listen(8800, '127.0.0.1', () => r()))

const engine = new ProxyEngine()
await engine.start(8899)
const api = new ApiServer(engine, {}, { port: 8877, flowCap: 100 })
await api.start()

// 制造流量（注意：代理 URL 必须带完整 http:// 前缀，否则自环转发到代理自己）
await new Promise<void>((r) => {
  const req = httpGet({ host: '127.0.0.1', port: 8899, path: 'http://127.0.0.1:8800/a', headers: { host: '127.0.0.1:8800' } }, (res) => { res.resume(); res.on('end', r) })
  req.end()
})

// ---- T1: status ----
const st = await (await fetch(`${BASE}/api/status`)).json() as any
assert.equal(st.proxy.running, true)
assert.equal(st.upstream.type, 'direct')

// ---- T2: flows 查询 ----
let j = await (await fetch(`${BASE}/api/flows`)).json() as any
assert.ok(j.items.length >= 1, `items=${j.items.length}`)
const first = j.items[0]
assert.ok(first.method && first.url && typeof first.status === 'number')

// ---- T3: 单条查询 ----
const one = await (await fetch(`${BASE}/api/flows/${first.id}`)).json() as any
assert.equal(one.id, first.id)

// ---- T4: 增量 after ----
const next = await (await fetch(`${BASE}/api/flows?after=${first.id}`)).json() as any
assert.ok(!next.items.some((x: any) => x.id <= first.id), 'after 增量正确')

// ---- T5: PUT upstream ----
const put = await (await fetch(`${BASE}/api/upstream`, {
  method: 'PUT', headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ type: 'socks5', host: '127.0.0.1', port: 1080 }),
})).json() as any
assert.equal(put.ok, true)
const st2 = await (await fetch(`${BASE}/api/status`)).json() as any
assert.equal(st2.upstream.type, 'socks5')
engine.setUpstream({ type: 'direct' }) // 还原

// ---- T6: SSE 实时事件 ----
const events: any[] = []
await new Promise<void>((resolve, reject) => {
  const req = httpGet(`${BASE}/api/events`, (res) => {
    res.setEncoding('utf-8')
    res.on('data', (d) => {
      for (const line of d.split('\n')) {
        if (line.startsWith('data: ')) {
          events.push(JSON.parse(line.slice(6)))
          if (events.some((e) => e.method === 'GET' && e.url.includes('/sse'))) resolve()
        }
      }
    })
    res.on('error', reject)
  })
  req.on('error', reject)
  setTimeout(() => reject(new Error('SSE timeout')), 5000)
  // 制造触发 SSE 的流量
  setTimeout(() => {
    const r2 = httpGet({ host: '127.0.0.1', port: 8899, path: 'http://127.0.0.1:8800/sse', headers: { host: '127.0.0.1:8800' } }, (res) => res.resume())
    r2.end()
  }, 200)
})
assert.ok(events.length >= 1, `sse events=${events.length}`)

console.log('sse events:', events.map((e) => `#${e.id} ${e.method} ${e.url}`).join(' | '))
console.log('\nALL PASS ✓')
process.exit(0)
