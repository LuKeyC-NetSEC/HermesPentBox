/** VULNDOC 解析器单元测试：core/vulndoc.ts */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { parseVulndoc } from './vulndoc.ts'

const DOC = `【VULNDOC】
标题：/api/login 未授权访问
危害等级：high
漏洞描述：登录接口存在未授权访问
复现步骤：直接 GET /api/login 返回敏感数据
修复建议：添加鉴权
漏洞目标：http://127.0.0.1:8800
漏洞路由：/api/login
原始请求包：
GET /api/login HTTP/1.1
Host: 127.0.0.1:8800

原始响应包：
HTTP/1.1 200 OK
Content-Type: application/json

{"data":"secret"}
`

test('parseVulndoc：标准【VULNDOC】完整解析', () => {
  const p = parseVulndoc(DOC)
  assert.ok(p)
  assert.equal(p!.name, '未授权访问')  // 标题去掉路由前缀
  assert.equal(p!.level, 'high')
  assert.equal(p!.uri, 'http://127.0.0.1:8800/api/login')
  assert.ok(p!.desc.includes('未授权访问'))
  assert.ok(p!.desc.includes('修复建议：添加鉴权'))
  assert.equal(p!.exploit, '直接 GET /api/login 返回敏感数据')
  assert.ok(p!.reqRaw.includes('GET /api/login HTTP/1.1'))
  assert.ok(p!.resRaw.includes('{"data":"secret"}'))
})

test('parseVulndoc：兼容省略【VULNDOC】标记（有"原始请求包："即识别）', () => {
  const noMark = DOC.replace('【VULNDOC】\n', '')
  const p = parseVulndoc(noMark)
  assert.ok(p)
  assert.equal(p!.level, 'high')
})

test('parseVulndoc：危害等级关键词匹配（中/低）', () => {
  const medium = parseVulndoc(DOC.replace('危害等级：high', '危害等级：medium'))
  assert.equal(medium!.level, 'medium')
  const cnLow = parseVulndoc(DOC.replace('危害等级：high', '危害等级：低'))
  assert.equal(cnLow!.level, 'low')
  const unknown = parseVulndoc(DOC.replace('危害等级：high', '危害等级：未知'))
  assert.equal(unknown!.level, 'info')
})

test('parseVulndoc：无文档返回 null', () => {
  assert.equal(parseVulndoc('该接口无漏洞，测试完成'), null)
  assert.equal(parseVulndoc(''), null)
})

test('parseVulndoc：markdown 围栏清洗 + 兜底原始报文', () => {
  const withFence = DOC.replace('GET /api/login HTTP/1.1', '```\nGET /api/login HTTP/1.1')
  const p = parseVulndoc(withFence, 'FALLBACK_REQ', 'FALLBACK_RES')
  assert.ok(!p!.reqRaw.includes('```'))
  assert.ok(p!.reqRaw.includes('GET /api/login'))
  // 模型未输出请求包时用兜底
  const noRaw = parseVulndoc(DOC.split('原始请求包：')[0], 'FALLBACK_REQ')
  assert.equal(noRaw!.reqRaw, 'FALLBACK_REQ')
})

test('parseVulndoc：标题为空时默认名', () => {
  const noTitle = DOC.replace('标题：/api/login 未授权访问\n', '')
  const p = parseVulndoc(noTitle)
  assert.equal(p!.name, '子 Agent 渗透发现')
})
