/** 纯函数单元测试：core/utils.ts（node:test 零依赖） */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { normalizeTargetKey, resStatus, extractJson, STATIC_RESOURCE_RE, LOCAL_ARTIFACT_RE, isBrowserBuiltin, isPentboxOwnTraffic } from './utils.ts'

test('normalizeTargetKey：协议去除 + host 小写 + 保留端口/路径/查询', () => {
  assert.equal(normalizeTargetKey('https://EXAMPLE.com:8443/api/login?x=1'), 'example.com:8443/api/login?x=1')
  assert.equal(normalizeTargetKey('http://a.com/path'), 'a.com/path')
  assert.equal(normalizeTargetKey('a.com:8080/x'), 'a.com:8080/x')
  assert.equal(normalizeTargetKey(''), '')
  assert.equal(normalizeTargetKey('http://x.com'), 'x.com/')  // new URL 根路径为 '/'
})

test('resStatus：从 resLine 解析状态码', () => {
  assert.equal(resStatus({ resLine: 'HTTP/1.1 404 Not Found' }), 404)
  assert.equal(resStatus({ resLine: 'HTTP/1.1 200 OK' }), 200)
  assert.equal(resStatus({ resLine: 'HTTP/2 500' }), 500)
  assert.equal(resStatus(undefined), 0)
  assert.equal(resStatus({}), 0)
})

test('extractJson：括号配对提取首个 JSON（容忍前后杂文/嵌套字符串）', () => {
  const r = extractJson('前置说明 {"a":1,"b":{"c":"x{y}"}} 后置杂文')
  assert.deepEqual(r, { a: 1, b: { c: 'x{y}' } })
  assert.equal(extractJson('无 JSON'), null)
  assert.deepEqual(extractJson('{"vuln":true,"advice":"测试"}'), { vuln: true, advice: '测试' })
  assert.equal(extractJson('{"broken":'), null)
})

test('STATIC_RESOURCE_RE：静态资源判定（防误报意见卡）', () => {
  assert.ok(STATIC_RESOURCE_RE.test('http://x.com/static/a.js'))
  assert.ok(STATIC_RESOURCE_RE.test('http://x.com/img/topnav/newzhibo-a6a0831ecd.png'))
  assert.ok(STATIC_RESOURCE_RE.test('http://x.com/favicon.ico'))
  assert.ok(STATIC_RESOURCE_RE.test('http://x.com/a.gif?logactid=123'))
  assert.ok(STATIC_RESOURCE_RE.test('http://x.com/basics/chat/afx.mp4'))
  assert.ok(STATIC_RESOURCE_RE.test('http://x.com/app.css?v=md5'))
  // 真实接口不应命中
  assert.ok(!STATIC_RESOURCE_RE.test('http://x.com/api/login'))
  assert.ok(!STATIC_RESOURCE_RE.test('http://x.com/ztbox?action=zpblog'))
  assert.ok(!STATIC_RESOURCE_RE.test('http://x.com/sugrec?prod=pc_his'))
  assert.ok(!STATIC_RESOURCE_RE.test('http://x.com/'))
})

test('LOCAL_ARTIFACT_RE：本机工件/客户端噪音剔除', () => {
  assert.ok(LOCAL_ARTIFACT_RE.test('C:\\Users\\Admin\\secret.txt'))
  assert.ok(LOCAL_ARTIFACT_RE.test('localhost:8080'))
  assert.ok(LOCAL_ARTIFACT_RE.test('127.0.0.1'))
  assert.ok(!LOCAL_ARTIFACT_RE.test('password=admin123'))
})

test('isBrowserBuiltin：浏览器内置流量黑名单', () => {
  assert.ok(isBrowserBuiltin({}, 'http://update.googleapis.com/service/update2/json'))
  assert.ok(isBrowserBuiltin({}, 'https://clients4.google.com/generate_204'))
  assert.ok(isBrowserBuiltin({}, 'https://detectportal.firefox.com/canonical.html'))
  assert.ok(isBrowserBuiltin({}, 'https://ocsp.digicert.com/abc'))
  assert.ok(!isBrowserBuiltin({}, 'http://192.168.1.1/api/login'))
  assert.ok(!isBrowserBuiltin(undefined, 'http://target.com/x'))
})

test('isPentboxOwnTraffic：应用自身流量（x-pentbox-source 标记）', () => {
  assert.ok(isPentboxOwnTraffic({ reqHeaders: { 'x-pentbox-source': 'webshell' } }))
  assert.ok(isPentboxOwnTraffic({ reqHeaders: { 'x-pentbox-source': 'repeater' } }))
  assert.ok(!isPentboxOwnTraffic({ reqHeaders: {} }))
  assert.ok(!isPentboxOwnTraffic(undefined))
})
