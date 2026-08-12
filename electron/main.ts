/**
 * HermesPentBox Electron 主进程
 * 装配：代理引擎(8899) + API/SSE(8877) + 终端WS(8878) + Chrome/Firefox + SSH
 * 浏览器流量与代理流量汇入同一流量库（source 区分）
 */
import { app, BrowserWindow, Menu, ipcMain } from 'electron'
import { join } from 'node:path'
import { WebSocketServer } from 'ws'
import { ProxyEngine } from '../core/proxy.ts'
import { ApiServer } from '../core/api.ts'
import { ChromeBrowser } from '../core/browser.ts'
import { FirefoxBrowser } from '../core/firefox.ts'
import { SshSession } from '../core/ssh.ts'

const L = ApiServer.loadListen()  // 监听配置（设置-网络配置-监听设置：监听地址 + 主服务端口，重启生效）
const PROXY_PORT = Number(process.env.PENTBOX_PROXY_PORT ?? 8899)
const API_PORT = L.api
const WS_PORT = Number(process.env.PENTBOX_WS_PORT ?? 8878)
const LISTEN_IP = L.ip

function startTerminalWs(ssh: SshSession): void {
  const wss = new WebSocketServer({ port: WS_PORT, host: LISTEN_IP })
  wss.on('connection', (ws) => {
    let shell: NodeJS.ReadWriteStream | null = null
    ws.on('message', async (raw) => {
      try {
        const msg = JSON.parse(raw.toString())
        if (msg.type === 'connect') {
          await ssh.connect(msg.opts)
          shell = await ssh.shell()
          shell.on('data', (d) => ws.send(JSON.stringify({ type: 'data', data: d.toString() })))
          shell.on('close', () => ws.send(JSON.stringify({ type: 'closed' })))
          ws.send(JSON.stringify({ type: 'ready' }))
        } else if (msg.type === 'input' && shell) {
          shell.write(msg.data)
        } else if (msg.type === 'resize' && shell && (shell as any).setWindow) {
          ;(shell as any).setWindow(msg.rows, msg.cols)
        } else if (msg.type === 'exec') {
          const r = await ssh.exec(msg.command, { timeout: 30000 })
          ws.send(JSON.stringify({ type: 'exec-result', ...r }))
        }
      } catch (e) {
        ws.send(JSON.stringify({ type: 'error', error: e instanceof Error ? e.message : String(e) }))
      }
    })
    ws.on('close', () => shell?.end())
  })
}

app.whenReady().then(async () => {
  const engine = new ProxyEngine()
  // 默认上游 = 系统代理（保证浏览器走内置代理时能出网）；无系统代理则直连
  const sysProxy = engine.detectSystemProxy()
  if (sysProxy) engine.setUpstream(sysProxy)
  // MITM 默认开启（打开浏览器即抓 HTTPS 明文）
  engine.mitmEnabled = true
  console.log(`[pentbox] upstream=${engine.upstreamLabel()} mitm=on`)
  await engine.start(PROXY_PORT, LISTEN_IP)
  const chrome = new ChromeBrowser()
  const firefox = new FirefoxBrowser()
  const ssh = new SshSession()
  const api = new ApiServer(engine, { chrome, firefox, ssh }, { port: API_PORT, proxyPort: PROXY_PORT, host: LISTEN_IP })
  await api.start()
  // 浏览器流量汇入统一流量库
  // MITM 开启时流量已由代理引擎全量捕获（含详情），跳过 CDP 冗余记录避免 http/https 双条
  chrome.onFlow = (f) => { if (!engine.mitmEnabled) api.push(f) }
  firefox.onFlow = (f) => { if (!engine.mitmEnabled) api.push(f) }
  // WS 帧汇入 WebSockets History
  chrome.onWsFrame = (f) => api.pushWs(f)
  startTerminalWs(ssh)

  const win = new BrowserWindow({
    width: 1400,
    height: 900,
    title: 'HermesPentBox',
    backgroundColor: '#111418',
    autoHideMenuBar: true,  // 隐藏 File/Edit/View/Window 菜单栏
    webPreferences: { contextIsolation: true, nodeIntegration: false, preload: join(app.getAppPath(), 'electron', 'preload.js') },
  })
  Menu.setApplicationMenu(null)  // 彻底移除默认菜单栏（File/Edit/View/Window）
  // 自定义窗口控制（renderer 经 preload 调 win-control）
  ipcMain.on('win-control', (e, act: string) => {
    const w = BrowserWindow.fromWebContents(e.sender)
    if (!w) return
    if (act === 'min') w.minimize()
    else if (act === 'max') (w.isMaximized() ? w.unmaximize() : w.maximize())
    else if (act === 'close') w.close()
  })
  await win.loadFile('ui/index.html')

  win.on('closed', () => app.quit())
})

app.on('window-all-closed', () => {
  app.quit()
})
