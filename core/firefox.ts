/**
 * Firefox 浏览器控制（Burp 方式：独立进程 + 自定义 profile 代理指向内置 8899）
 * playwright 的 BiDi launcher（moz-firefox）忽略 args/proxy/firefoxUserPrefs（实测 Firefox 走系统代理 7890 抓不到流量）
 * 改为直接 spawn firefox.exe：-profile（预建 user.js 写死代理）→ 所有流量统一走 8899 MITM，用户手动导航（Burp 同款体验）
 */
import { spawn, type ChildProcess } from 'node:child_process'
import { existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

export interface FirefoxOptions {
  proxyPort?: number       // 浏览器代理指向内置代理引擎
  customProxy?: string     // 自定义代理 host:port（如 Burp 127.0.0.1:8889），优先于 proxyPort
  executablePath?: string  // firefox 可执行文件（默认系统安装）
  headless?: boolean
  url?: string             // 启动时打开的初始地址
}

export function firefoxExecutable(): string {
  const env = process.env.FIREFOX_PATH
  if (env && existsSync(env)) return env
  const candidates =
    process.platform === 'win32'
      ? [
          'C:\\Program Files\\Firefox Developer Edition\\firefox.exe',
          'C:\\Program Files\\Mozilla Firefox\\firefox.exe',
          'C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe',
        ]
      : ['/usr/bin/firefox', '/usr/bin/firefox-esr']
  const hit = candidates.find((p) => existsSync(p))
  if (!hit) throw new Error('Firefox not found, set FIREFOX_PATH (or run: npx playwright install firefox)')
  return hit
}

export class FirefoxBrowser {
  private proc: ChildProcess | null = null
  private running = false

  async launch(opts: FirefoxOptions = {}): Promise<void> {
    // 预建 profile + user.js：代理写死指向内置 8899（Burp 方式统一代理捕获）
    const profileDir = join(tmpdir(), 'pentbox-ff-' + Date.now())
    mkdirSync(profileDir, { recursive: true })
    const proxyServer = opts.customProxy
      ? `http://${opts.customProxy}`
      : `http://127.0.0.1:${opts.proxyPort ?? 8899}`  // 与 Chrome 一致：未显式传 proxyPort 时兜底内置代理 8899
    if (proxyServer) {
      const [ph, pp] = proxyServer.replace(/^http:\/\//, '').split(':')
      writeFileSync(join(profileDir, 'user.js'), [
        'user_pref("network.proxy.type", 1);',
        `user_pref("network.proxy.http", "${ph}");`,
        `user_pref("network.proxy.http_port", ${pp});`,
        `user_pref("network.proxy.ssl", "${ph}");`,
        `user_pref("network.proxy.ssl_port", ${pp});`,
        'user_pref("network.proxy.no_proxies_on", "");',
        // MITM 证书信任：Firefox 默认不读 Windows 系统根证书库（不像 Chrome 有 --ignore-certificate-errors），
        // 必须开启 enterprise_roots 才能信任已安装的 pentbox CA，否则 HTTPS 全部报"连接不安全"抓不到包
        'user_pref("security.enterprise_roots.enabled", true);',
      ].join('\n'))
    }
    const args = ['-profile', profileDir, '-no-remote']
    if (opts.headless) args.push('-headless')
    if (opts.url) args.push(opts.url)
    this.proc = spawn(opts.executablePath ?? firefoxExecutable(), args, { detached: true, stdio: 'ignore' })
    this.proc.unref()
    this.running = true
  }

  isRunning(): boolean {
    return this.running
  }

  /** 独立进程无法脚本导航（Burp 同款：用户在浏览器窗口手动操作）；初始地址在 launch 时通过 url 传入 */
  async navigate(_url: string): Promise<void> {
    throw new Error('Firefox 独立模式：请在浏览器窗口手动导航（launch 时可带 url）')
  }

  async evaluate(_expression: string): Promise<unknown> {
    throw new Error('Firefox 独立模式：不支持 evaluate')
  }

  async getResponseBody(_url: string): Promise<string> {
    return ''
  }

  async stop(): Promise<void> {
    if (this.proc) { try { this.proc.kill() } catch { /* 已退出 */ } }
    this.proc = null
    this.running = false
  }
}
