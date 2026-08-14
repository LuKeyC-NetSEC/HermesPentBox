/**
 * 纯函数工具集：从 ApiServer 提取的可独立测试逻辑（无副作用）
 * 供核心逻辑单元测试（node:test）与 api.ts 复用
 */

/** 目标 URL 统一规范化 key（P0：发卡去重/渗透前查重/成果写入三处共用，保证格式一致）：
 * 去协议、host 小写、保留端口（显式时）+ 路径 + 查询参数；如 https://EXAMPLE.com:8443/api/login?x=1 → example.com:8443/api/login?x=1 */
export function normalizeTargetKey(input: string): string {
  if (!input) return ''
  try {
    const u = new URL(input.includes('://') ? input : `http://${input}`)
    const host = (u.hostname || '').toLowerCase()
    const port = u.port ? `:${u.port}` : ''
    return `${host}${port}${u.pathname}${u.search}`
  } catch {
    return input.replace(/^https?:\/\//i, '').toLowerCase()
  }
}

/** 从报文快照解析响应状态码（resLine 形如 HTTP/1.1 404 Not Found） */
export function resStatus(detail?: unknown): number {
  const d = detail as { resLine?: string } | undefined
  const m = String(d?.resLine ?? '').match(/HTTP\/[\d.]+\s+(\d{3})/)
  return m ? Number(m[1]) : 0
}

/** 从 LLM 输出提取首个完整 JSON（括号配对，容忍前后杂文） */
export function extractJson(text: string): Record<string, unknown> | null {
  const i = text.indexOf('{')
  if (i < 0) return null
  let depth = 0
  let inStr = false
  for (let j = i; j < text.length; j++) {
    const c = text[j]
    if (inStr) { if (c === '\\') j++; else if (c === '"') inStr = false; continue }
    if (c === '"') inStr = true
    else if (c === '{') depth++
    else if (c === '}') { depth--; if (depth === 0) { try { return JSON.parse(text.slice(i, j + 1)) } catch { return null } } }
  }
  return null
}

/** 静态资源扩展名：js/css/图片/字体/媒体/文档/地图等——字段名/参数名不等于真凭据，且无独立渗透价值，命中不推意见卡（防误报刷屏）；凭据情报仍入库 */
export const STATIC_RESOURCE_RE = /\.(js|mjs|css|png|jpe?g|gif|webp|bmp|ico|svg|avif|woff2?|ttf|eot|otf|mp3|mp4|webm|ogg|avi|mov|zip|gz|7z|tar|rar|pdf|docx?|xlsx?|pptx?|map)(\?|#|$)/i

/** 本机工件/客户端请求头噪音特征：分析出的"敏感项"命中则视为非目标泄漏（脏情报不入图） */
export const LOCAL_ARTIFACT_RE = /(C:\\Users\\[^\\"'\s]+|\/Users\/[^\/"'\s]+|windows\/system32|localhost(?::\d+)?|127\.0\.0\.1|Proxy-Connection|Accept-Encoding|Accept-Language|Upgrade-Insecure-Requests|^Sec-Fetch-|Connection\s*:\s*keep-alive|User-Agent\s*:\s*curl)/i

/** 浏览器内置流量特征：Chrome/Edge/Firefox 更新、字典、时间同步、遥测、OCSP 证书状态等（旧实例日志实证样本） */
export const BROWSER_TRAFFIC = [
  /redirector\.gvt1\.com/,            // Chrome 字典/组件下载
  /edgedl\/chrome\/dict/,             // Chrome 拼写字典
  /clients\d*\.google\.com/,          // Chrome 时间同步/遥测
  /update\.googleapis\.com/,          // Chrome 更新服务
  /service\/update2\/json/,           // Chrome 更新轮询
  /\/time\/1\/current/,               // Google 时间同步
  /tools\.google\.com\/service\/update/, // 更新清单
  /safebrowsing\.googleapis\.com/,    // 安全浏览
  /accounts\.google\.com\/ListAccounts/,  // Chrome 账户轮询
  /content-autofill\.googleapis\.com/,    // Chrome 自动填充
  /connectivitycheck\.gstatic\.com/,  // 网络连通性探测
  /\/generate_204\//,                 // 连通性 204 探针
  /clientservices\.google\.com/,      // Chrome 遥测
  /accounts\.google\.com\/domainreliability/,  // 账户域可靠性上传
  /www\.google\.com\/async\//,                 // 首页异步功能（folae 等）
  /www\.google\.com\/complete\/search/,        // 地址栏自动补全（omnibox suggestions：client=chrome-omni 等）
  /ohttp_gateway/,                             // gstatic OHTTP 网关（隐私代理）
  /gvt1-cn\.com/,                              // 字典 CDN 镜像（sn-*.gvt1-cn.com）
  /update\.googleapis\.com/,                   // Chrome 组件更新服务
  /www\.googleapis\.com/,                      // Google API 遥测（chromewebstore verify 等）
  /chromewebstore\.googleapis\.com/,           // 扩展商店
  /android\.clients\.google\.com/,             // Chrome checkin
  /optimizationguide-pa\.googleapis\.com/,     // 优化指南模型
  /clientservices\.googleapis\.com/,           // uma 遥测
  /beacons\.gcp\.gvt2\.com/,                   // 域可靠性上传
  /ocsp\.(digicert|comodoca|pki\.goog|usertrust|globalsign)\./,  // OCSP 证书吊销检查
  /crl\.(digicert|comodoca|globalsign)\./,                       // CRL 吊销列表
  // ---- Firefox/Edge 内置遥测与系统流量（旧实例日志实证样本） ----
  /\.services\.mozilla\.com\//,                // Firefox 设置同步/地理位置/追踪保护列表（firefox.settings/location/shavar.*）
  /\.cdn\.mozilla\.net\//,                     // Firefox 设置附件/内容签名/远程配置 CDN
  /detectportal\.firefox\.com/,                // Firefox 网络连通性探测（captive portal）
  /firefox-settings\.mozilla-backup\.org/,     // Firefox 设置备份域
  /mozilla-ohttp\.fastly-edge\.com/,           // Firefox OHTTP 隐私网关
  /aus5\.mozilla\.org/,                        // Firefox 更新服务器
  /normandy\.(cdn\.)?mozilla\.(org|net)/,      // Firefox Normandy 实验/特性开关
  /snippets\.cdn\.mozilla\.net/,               // Firefox 新标签页摘要
  /accounts\.firefox\.com/,                    // Firefox 账户同步
  /shavar\.services\.mozilla\.com/,            // Firefox 跟踪保护列表（Safe Browsing 分流）
  /incoming\.telemetry\.mozilla\.org/,         // Firefox 遥测上报
  /firefox\.cloud\.mozilla\.com/,              // Firefox 云
  // ---- Firefox 自带页面/下载/扩展/广告（旧实例日志实证样本） ----
  /www\.mozilla\.org/,                         // Firefox 新标签页/欢迎/下载页
  /gtm\.mozilla\.org/,                         // Mozilla GTM 遥测
  /ads\.mozilla\.org/,                         // Mozilla 广告
  /download\.mozilla\.org/,                    // Firefox 下载服务器
  /services\.addons\.mozilla\.org/,            // Firefox 扩展商店
  /\.mozgcp\.net/,                             // Mozilla GCP 网关（OHTTP 生产网关）
  /ciscobinary\.openh264\.org/,                // Firefox OpenH264 编解码器下载
]

/** 是否命中浏览器内置流量（更新/字典/遥测/OCSP 等）：命中则跳过 Agent 审计 */
export function isBrowserBuiltin(detail?: unknown, url?: string): boolean {
  const s = (typeof detail === 'string' ? detail : JSON.stringify(detail ?? '')) + ' ' + (url ?? '')  // url 参与匹配（detail 无路径时黑名单 URL 规则仍命中）
  if (!s.trim()) return false
  return BROWSER_TRAFFIC.some((re) => re.test(s))
}

/** HermesPentBox 自身流量（WebShell 命令执行 / Repeater 等）：请求带 x-pentbox-source 标记头 → 跳过 Agent 审计 */
export function isPentboxOwnTraffic(detail?: unknown): boolean {
  const reqHeaders = (detail as { reqHeaders?: Record<string, string> })?.reqHeaders
  if (reqHeaders) {
    const src = String(reqHeaders['x-pentbox-source'] || '').toLowerCase()
    if (src === 'webshell' || src === 'repeater') return true
  }
  const s = typeof detail === 'string' ? detail : JSON.stringify(detail ?? '')
  return /x-pentbox-source[":]?\s*["']?(webshell|repeater)/i.test(s)
}

// 规则层已移除（用户决定：纯 Agent 审批——破坏性判断全部交给审批官 Agent）
