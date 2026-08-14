/** HaENet 标签体系单元测试：core/tags.ts */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { HAE_TAGS, HAE_GROUPS, HAE_CRED_TAGS, HAE_LEVEL_COLOR, haeTagList } from './tags.ts'

test('HAE_TAGS：注册表完整（42 标签，字段齐全）', () => {
  const names = Object.keys(HAE_TAGS)
  assert.ok(names.length >= 40)
  for (const [k, t] of Object.entries(HAE_TAGS)) {
    assert.ok(['Fingerprint', 'Maybe Vulnerability', 'Basic Information', 'Sensitive Information', 'Other'].includes(t.group), `${k} group`)
    assert.ok(typeof t.cn === 'string' && t.cn.length > 0, `${k} cn`)
    assert.ok(['high', 'medium', 'low', 'info'].includes(t.level), `${k} level`)
    assert.ok(/^#[0-9a-f]{6}$/i.test(t.color), `${k} color`)
  }
})

test('HAE_TAGS：5 组均覆盖', () => {
  for (const g of HAE_GROUPS) {
    const count = Object.values(HAE_TAGS).filter((t) => t.group === g.key).length
    assert.ok(count > 0, `${g.cn}(${g.key}) 有 ${count} 个标签`)
  }
})

test('HAE_CRED_TAGS：凭据类标签均在 Sensitive Information 组且为 high', () => {
  for (const tag of HAE_CRED_TAGS) {
    assert.ok(HAE_TAGS[tag], `标签 ${tag} 已注册`)
    assert.equal(HAE_TAGS[tag].group, 'Sensitive Information', `${tag} 组`)
    assert.equal(HAE_TAGS[tag].level, 'high', `${tag} 等级`)
  }
})

test('HAE_LEVEL_COLOR：四级色齐全', () => {
  for (const lv of ['high', 'medium', 'low', 'info']) {
    assert.ok(/^#[0-9a-f]{6}$/i.test(HAE_LEVEL_COLOR[lv]), lv)
  }
})

test('haeTagList：渲染包含全部组与标签名', () => {
  const text = haeTagList()
  assert.ok(text.includes('敏感信息(Sensitive Information)'))
  assert.ok(text.includes('API Key'))
  assert.ok(text.includes('Nday 组件'))
  for (const g of HAE_GROUPS) assert.ok(text.includes(g.cn), g.cn)
})
