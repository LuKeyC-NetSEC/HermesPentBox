/**
 * HermesPentBox Electron 主进程
 * 装配：代理引擎(8899) + API/SSE(8877) + 终端WS(8878) + Chrome/Firefox + SSH
 * 浏览器流量与代理流量汇入同一流量库（source 区分）
 */
// 主进程 stdout/stderr 管道可能被宿主回收（后台启动/重定向退出后管道关闭）：
// console.log 写入已断开管道会抛 EPIPE 未捕获异常导致整个主进程崩溃（如自动保存定时器里的日志）。
// 挂空 error 处理器吞掉 EPIPE，保证应用在无控制台/管道断开时稳定运行。
process.stdout.on('error', () => {})
process.stderr.on('error', () => {})
import { app, BrowserWindow, Menu, ipcMain, dialog } from 'electron'
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
/** 模块级引用：退出前兜底保存会话快照（类 Burp 项目文件 auto-save）+ 统一清理常驻进程 + 保存项目对话框父窗口 */
let api: ApiServer | null = null
let win: BrowserWindow | null = null
let chrome: ChromeBrowser | null = null
let firefox: FirefoxBrowser | null = null

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
  console.log('[pentbox] step: engine started')
  chrome = new ChromeBrowser()
  firefox = new FirefoxBrowser()
  const ssh = new SshSession()
  api = new ApiServer(engine, { chrome, firefox, ssh }, { port: API_PORT, proxyPort: PROXY_PORT, host: LISTEN_IP })
  await api.start()
  console.log('[pentbox] step: api started')
  // 浏览器流量汇入统一流量库
  // MITM 开启时流量已由代理引擎全量捕获（含详情），跳过 CDP 冗余记录避免 http/https 双条
  chrome!.onFlow = (f) => { if (!engine.mitmEnabled) api!.push({ ...f, upstream: 'browser' }) }
  // Firefox 流量统一经代理引擎捕获（firefox.ts 无 CDP 流量回调），无需额外汇入
  // WS 帧汇入 WebSockets History
  chrome!.onWsFrame = (f) => api!.pushWs(f)
  startTerminalWs(ssh)

  // 类 Burp：恢复上次窗口位置/大小（存于 config.bin 全局配置）
  const wb = ApiServer.loadWinBounds()
  win = new BrowserWindow({
    width: wb?.width || 1400,
    height: wb?.height || 900,
    ...(wb?.x !== undefined && wb.y !== undefined ? { x: wb.x, y: wb.y } : {}),
    title: 'HermesPentBox',
    backgroundColor: '#111418',
    autoHideMenuBar: true,  // 隐藏 File/Edit/View/Window 菜单栏
    webPreferences: { contextIsolation: true, nodeIntegration: false, preload: join(app.getAppPath(), 'electron', 'preload.js') },
  })
  win.on('close', () => { try { ApiServer.saveWinBounds(win!.getBounds()) } catch { /* 保存失败不影响退出 */ } })  // 记住窗口状态
  // 诊断：捕获渲染器 console 错误（临时排查用）
  win.webContents.on('console-message', (_e, level, message, line, sourceId) => {
    if (level >= 2) console.log(`[renderer:${level}] ${message} (${sourceId}:${line})`)
  })
  Menu.setApplicationMenu(null)  // 彻底移除默认菜单栏（File/Edit/View/Window）
  // 项目管理：保存项目 → 弹系统保存对话框选择路径/自定义文件名（renderer 经 preload invoke）
  ipcMain.handle('save-project-dialog', async (e, defaultPath?: string) => {
    const w = BrowserWindow.fromWebContents(e.sender) ?? win
    const r = await dialog.showSaveDialog(w!, {
      title: '保存项目',
      defaultPath: defaultPath || undefined,
      filters: [{ name: 'HermesPentBox 项目', extensions: ['hpbs'] }],
      properties: ['createDirectory', 'showOverwriteConfirmation'],
    })
    return r.canceled ? null : r.filePath
  })
  // 自定义窗口控制（renderer 经 preload 调 win-control）
  ipcMain.on('win-control', (e, act: string) => {
    const w = BrowserWindow.fromWebContents(e.sender)
    if (!w) return
    if (act === 'min') w.minimize()
    else if (act === 'max') (w.isMaximized() ? w.unmaximize() : w.maximize())
    else if (act === 'close') w.close()
  })
  await win!.loadFile('ui/index.html')
  console.log('[pentbox] step: window loaded')

  win!.on('closed', () => app.quit())
})

app.on('window-all-closed', () => {
  app.quit()
})

// 退出前兜底：保存会话快照 + 统一停止常驻子进程（bridge/gateway/suo5/浏览器，防 detached 残留）
app.on('before-quit', () => {
  try { api?.saveSession() } catch { /* 保存失败不阻塞退出 */ }
  try { api?.stopAllProcesses() } catch { /* 清理失败不阻塞退出 */ }
  try { chrome?.stop() } catch { /* 已退出 */ }
  try { firefox?.stop() } catch { /* 已退出 */ }
})
