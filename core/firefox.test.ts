/**
 * Firefox 集成自测：launch Developer Edition → navigate 本地目标 → 流量捕获
 */
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { FirefoxBrowser } from './firefox.ts'

const target = createServer((q, s) => {
  if (q.url === '/') {
    s.writeHead(200, { 'content-type': 'text/html' })
    s.end('<html><head><title>FFTest</title></head><body><h1>hi</h1><script>fetch("/api/x")</script></body></html>')
  } else {
    s.writeHead(200, { 'content-type': 'application/json' })
    s.end('{"ok":true}')
  }
})
await new Promise<void>((r) => target.listen(8800, '127.0.0.1', () => r()))

const flows: any[] = []
const b = new FirefoxBrowser()
b.onFlow = (f) => flows.push(f)
await b.launch({ headless: true })

await b.navigate('http://127.0.0.1:8800/')
await new Promise((r) => setTimeout(r, 2500))

const title = await b.evaluate('document.title')
assert.equal(title, 'FFTest', `title=${title}`)

const doc = flows.find((f) => f.url === 'http://127.0.0.1:8800/')
assert.ok(doc && doc.status === 200, `doc flow: ${JSON.stringify(doc)}`)
const api = flows.find((f) => f.url.includes('/api/x'))
assert.ok(api && api.status === 200, `api flow: ${JSON.stringify(api)}`)

const body = await b.getResponseBody('http://127.0.0.1:8800/api/x')
assert.ok(body.includes('"ok":true'), `body=${body}`)

const shot = await b.screenshot()
assert.ok(shot.length > 1000, `screenshot ${shot.length}B`)

console.log('ff flows:')
for (const f of flows) console.log(`  #${f.id} ${f.method} ${f.url} -> ${f.status} ${f.bytes}B`)
console.log('title:', title, '| screenshot:', shot.length, 'B | api body ok')
await b.stop()
console.log('\nALL PASS ✓')
process.exit(0)
