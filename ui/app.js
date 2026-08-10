// HermesPentBox renderer：三面板（流量 / 浏览器 / SSH终端），全部走本地 HTTP API + WS
const API = 'http://127.0.0.1:8877'
const WS = 'ws://127.0.0.1:8878'

// ---- tab 切换 ----
// ---- 面包屑标题：HermesPentBox / 面板 / 子页 ----
const PANEL_NAMES = { flows: 'Proxy', sitemap: 'Site Map', vulns: 'Vulnerabilities', browser: 'Browser', term: 'SSH Terminal', settings: 'Settings' }
const FTAB_NAMES = { intercept: 'Intercept', http: 'HTTP History', repeater: 'Repeater', ws: 'WebSockets History' }
function setAppTitle(panel) {
  const el = document.getElementById('appTitle')
  const base = 'HermesPentBox / ' + (PANEL_NAMES[panel] || panel)
  el.textContent = panel === 'flows'
    ? base + ' / ' + (FTAB_NAMES[document.querySelector('.ftab.active')?.dataset.ftab] || 'HTTP History')
    : base
}

document.querySelectorAll('nav button').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('nav button').forEach((b) => b.classList.remove('active'))
    document.querySelectorAll('.panel').forEach((p) => p.classList.remove('active'))
    btn.classList.add('active')
    document.getElementById('panel-' + btn.dataset.panel).classList.add('active')
    // 设置面板时隐藏左侧 Hermes Agent 对话框（设置界面不需要聊天框）
    document.getElementById('aiChat').style.display = btn.dataset.panel === 'settings' ? 'none' : 'flex'
    setAppTitle(btn.dataset.panel)
    if (btn.dataset.panel === 'vulns') loadVulns()  // 切到漏洞面板时拉最新列表（Agent/外部可能已增改）
    if (btn.dataset.panel === 'sitemap') {
      refreshSitemap()  // 切到 Site Map 拉全量构建树
      if (!smTimer) smTimer = setInterval(refreshSitemap, 2000)  // Site Map 激活时实时刷新（新流量自动进树）
    } else if (smTimer) { clearInterval(smTimer); smTimer = null }
    // 面板级详情状态：各自记住打开过的流量，切回时恢复（HTTP History 与 Site Map 互不干扰）
    const st = detailStates[btn.dataset.panel]
    if (st) showFlowDetail(st.id, st.method, st.url)
    else flowDetail.style.display = 'none'
  })
})
const detailStates = {}  // panel → {id, method, url} | undefined：各面板独立记住打开的详情

// ---- Launch Browser（header 按钮 → 弹窗选 Chrome/Firefox → 调后端启动） ----
const pick = document.getElementById('browserPick')
const launchPick = async (engine) => {
  pick.style.display = 'none'
  try {
    await fetch(`${API}/api/browser/launch`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ engine }) })
  } catch { /* 启动失败忽略 */ }
}
document.getElementById('btnLaunchBrowser').onclick = () => { pick.style.display = 'flex' }
document.getElementById('btnPickChrome').onclick = () => launchPick('chrome')
document.getElementById('btnPickFirefox').onclick = () => launchPick('firefox')
document.getElementById('btnPickCancel').onclick = () => { pick.style.display = 'none' }
pick.onclick = (e) => { if (e.target === pick) pick.style.display = 'none' }  // 点遮罩关闭

// ---- AI 对话框（左侧常驻；与本地 Hermes Agent 对话，后端 /api/chat 保持会话上下文） ----
const aiMsgs = document.getElementById('aiChatMsgs')
const aiInput = document.getElementById('aiChatInput')
// 流量多选：Ctrl/Shift 选中多条（无复选框），发送时携带完整请求/响应数据包
const selFlowIds = new Set()
let lastSelFlowId = null
const deletedFlowIds = new Set()  // 假删除（右键 Delete Selected：HTTP History 移除，站点地图/后端保留）
const smSelFlowIds = new Set()  // 站点地图选中的流量 id（不受假删除影响——站点地图可发被假删除的流量）
const aiSelBar = document.getElementById('aiSelBar')
function renderAiSelBar() {
  const n = selFlowIds.size
  const vn = selVulnIds.size
  aiSelBar.style.display = (n || vn) ? 'flex' : 'none'
  document.getElementById('aiSelCount').textContent = `已选中流量 ${n} 条${vn ? `，漏洞 ${vn} 条` : ''}`
}
function clearAiSel() {
  selFlowIds.clear()
  lastSelFlowId = null
  selVulnIds.clear()
  lastSelVulnId = null
  renderAiSelBar()
  document.querySelectorAll('#flowTable tr.sel').forEach((tr) => tr.classList.remove('sel'))
}
document.getElementById('aiSelClear').onclick = clearAiSel
function addAiMsg(role, text) {
  const div = document.createElement('div')
  div.dataset.role = role
  div.style.cssText = role === 'user'
    ? 'align-self:flex-end;background:#1e3a5f;color:#d7e4f5;padding:6px 10px;border-radius:8px 8px 2px 8px;font-size:12px;max-width:85%;white-space:pre-wrap;word-break:break-word'
    : 'align-self:flex-start;background:#1c222c;color:#d7dde4;padding:6px 10px;border-radius:8px 8px 8px 2px;font-size:12px;max-width:85%;white-space:pre-wrap;word-break:break-word'
  div.textContent = text
  aiMsgs.appendChild(div)
  aiMsgs.scrollTop = aiMsgs.scrollHeight
  return div
}
// 子 Agent 运行跟踪：主聊天"回复子 Agent"或子 Agent 沟通窗口发起后，等待 penetrate-done SSE 送达结果
// key = slot → { show: (reply) => void }（展示回复 + 恢复 UI）
const pendingSubRuns = new Map()
// 主聊天 Send/Stop/Steer 按钮切换
const aiSendBtn = document.getElementById('aiChatSend')
let aiBusy = false  // 主聊天是否正在生成（防止并发）
let aiChatSid = ''  // 当前主对话的 bridge 会话 id（steer/status 用）
let aiStopFn = null // 运行中"停止"回调（abort）
let aiQueue = []    // 待发送队列（busy 时快速连发的消息排队，当前轮结束后自动发送）
function refreshAiSendBtn() {
  // 运行中：输入框有文字 → Steer（注入引导不打断）；空 → Stop（中断）
  if (aiBusy) {
    const hasText = aiInput.value.trim().length > 0
    if (hasText) {
      aiSendBtn.textContent = 'Steer'
      aiSendBtn.style.background = '#3a2a1e'
      aiSendBtn.style.color = '#f0b35c'
      aiSendBtn.title = '向运行中的 Agent 注入引导（不打断）'
      aiSendBtn.onclick = async () => {
        const text = aiInput.value.trim()
        if (!text) return
        aiInput.value = ''
        refreshAiSendBtn()
        try {
          const r = await fetch(`${API}/api/chat/steer`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text, sessionId: aiChatSid }) }).then((x) => x.json())
          // 复刻官方语义：仅运行中 accepted；空闲 rejected（提示而非静默）
          if (r.accepted) addAiMsg('ai', `↪ 已向运行中的 Agent 注入引导：${text}`)
          else addAiMsg('ai', `（当前 Agent 无活跃运行，引导未接受${r.reason ? `：${r.reason}` : ''}）`)
        } catch (e) { addAiMsg('ai', `（引导失败：${e.message}）`) }
      }
    } else {
      aiSendBtn.textContent = 'Stop'
      aiSendBtn.style.background = '#3a2020'
      aiSendBtn.style.color = '#f76b6b'
      aiSendBtn.title = '停止生成'
      aiSendBtn.onclick = () => { if (aiStopFn) aiStopFn() }
    }
  } else {
    aiSendBtn.textContent = 'Send'
    aiSendBtn.style.background = '#1e3a5f'
    aiSendBtn.style.color = '#4fc3f7'
    aiSendBtn.title = ''
    aiSendBtn.onclick = aiSend
  }
}
// 运行中监听输入变化切换 Steer/Stop
aiInput.addEventListener('input', refreshAiSendBtn)
function setAiSendBtn(running) {
  refreshAiSendBtn()
}
async function aiSend() {
  const msg = aiInput.value.trim()
  const selIds = [...selFlowIds].filter((id) => smSelFlowIds.has(id) || !deletedFlowIds.has(id))  // 站点地图选中的可发（含假删除）；流量表选中的过滤假删除
  const selN = selIds.length
  if (!msg && !selN && !selVulnIds.size) return
  // busy 并发保护：快速连发时消息入队（不丢弃、不产生假"思考中"气泡），当前轮结束后自动发送
  if (aiBusy) {
    if (msg && !selN && !selVulnIds.size) {
      aiInput.value = ''
      refreshAiSendBtn()  // 输入框清空后按钮回到 Stop
      const hint = addAiMsg('ai', `⏳ 已排队待发送：${msg.slice(0, 40)}`)
      aiQueue.push({ text: msg, el: hint })
    } else {
      addAiMsg('ai', '（Agent 正在工作中，请稍候再发送）')
    }
    return
  }
  let prompt = msg
  // 回复模式：点回复 ICON 后 = 与该子 Agent 沟通（消息走 /api/penetrate 到对应槽位会话）；不点则正常与主 Agent 对话
  if (aiReplyRef) {
    if (aiBusy) return
    aiBusy = true
    aiInput.placeholder = 'Ask Hermes...'
    const penMsg = `${msg}\n\n（回复渗透意见：${aiReplyRef}）`
    const penSlot = aiReplyRefSlot
    aiReplyRef = ''
    const think = addAiMsg('ai', '思考中…')
    setAiSendBtn(true)
    aiSendBtn.onclick = async () => {
      try { await fetch(`${API}/api/penetrate/cancel`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ slot: penSlot }) }) } catch { /* 已结束 */ }
      pendingSubRuns.delete(penSlot)
      think.remove()
      addAiMsg('ai', '✕ 已停止与子 Agent 沟通')
      aiBusy = false
      setAiSendBtn(false)
      aiSendBtn.onclick = aiSend
    }
    // 结果经 penetrate-done SSE 送达（/api/penetrate 异步返回 started:true）
    pendingSubRuns.set(penSlot, {
      show: (reply) => {
        think.remove()
        addAiMsg('ai', reply || '（子 Agent 无响应）')
        aiBusy = false
        setAiSendBtn(false)
        aiSendBtn.onclick = aiSend
      },
    })
    try {
      const pen = await fetch(`${API}/api/penetrate`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ advice: penMsg, slot: penSlot }) }).then((x) => x.json())
      // 后端查重直接拒绝（started:false + reply 立即返回）→ 不再等 SSE
      if (!pen.started) {
        pendingSubRuns.delete(penSlot)
        think.remove()
        addAiMsg('ai', pen.reply || '（子 Agent 无响应）')
        aiBusy = false
        setAiSendBtn(false)
        aiSendBtn.onclick = aiSend
      }
    } catch (e) {
      pendingSubRuns.delete(penSlot)
      think.remove()
      addAiMsg('ai', `（子 Agent 沟通失败：${e.message}）`)
      aiBusy = false
      setAiSendBtn(false)
      aiSendBtn.onclick = aiSend
    }
    return
  }
  if (selN) {
    // 实际发送：完整请求/响应数据包（多条拼接）+ 用户提示词
    const details = await Promise.all(selIds.map((id) => fetch(`${API}/api/flows/${id}/detail`).then((r) => r.json()).catch(() => null)))
    const blocks = details.filter(Boolean).map((d, i) =>
      `【流量 ${i + 1}】\n请求：\n${d.reqLine || ''}\n${fmtHeaders(d.reqHeaders, d.reqRawHeaders)}\n\n${fmtBody(d.reqBody)}\n\n响应：\n${d.resLine || ''}\n${fmtHeaders(d.resHeaders, d.resRawHeaders)}\n\n${fmtBody(d.resBody)}`)
    prompt = (msg ? msg + '\n\n' : '请分析以下选中的流量数据包：\n\n') + blocks.join('\n\n')
  }
  // 漏洞多选：完整 vulndoc（名称/等级/描述/利用信息/原始报文）→ 发给 AI
  if (selVulnIds.size) {
    const vds = await Promise.all([...selVulnIds].map((id) => fetch(`${API}/api/vulns/detail?id=${id}`).then((r) => r.json()).catch(() => null)))
    const vblocks = vds.filter(Boolean).map((v, i) =>
      `【漏洞 ${i + 1}】名称：${v.name}\n等级：${LEVEL_LABEL[v.level] || v.level}\nURI：${v.uri || '-'}\n描述：${v.desc || '(无)'}\n利用信息：${v.exploit || '(无)'}\n\n原始请求包：\n${v.reqRaw || '(无)'}\n\n原始响应包：\n${v.resRaw || '(无)'}`)
    prompt = (prompt ? prompt + '\n\n' : '请分析以下选中的漏洞文档：\n\n') + vblocks.join('\n\n')
  }
  aiInput.value = ''
  // 聊天框显示："已选中流量 N 条"（不展开完整数据包）
  addAiMsg('user', msg + (selN ? `\n（已选中流量 ${selN} 条）` : '') + (selVulnIds.size ? `\n（已选中漏洞 ${selVulnIds.size} 条）` : ''))
  const think = addAiMsg('ai', '思考中…')
  if (aiBusy) return  // 已在生成中（并发保护：Enter 连发/重复点击不重复发起）
  aiBusy = true
  let aborted = false
  const abort = new AbortController()
  aiStopFn = () => { aborted = true; abort.abort() }
  // 生成期间 Send → Stop/Steer（动态切换；结束后恢复 Send）
  setAiSendBtn(true)
  // 运行时长提示：Agent 推理/工具间隙无输出时，实时显示"已工作 Xs"（避免看起来像卡死）
  const thinkStart = Date.now()
  let lastActivity = Date.now()
  const thinkTimer = setInterval(() => {
    if (Date.now() - lastActivity < 2500) return  // 近期有输出，不覆盖真实内容
    const sec = Math.round((Date.now() - thinkStart) / 1000)
    think.textContent = `思考中…（已工作 ${sec}s）`
  }, 1000)
  const bumpActivity = () => { lastActivity = Date.now() }
  try {
    // SSE 流式对话（经本地 gateway，与渗透同通道）：delta 增量实时渲染（打字效果），done 收尾
    const r = await fetch(`${API}/api/chat`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ message: prompt, stream: true }), signal: abort.signal })
    const reader = r.body.getReader()
    const dec = new TextDecoder()
    let buf = ''
    let acc = ''
    think.innerHTML = ''  // 清掉"思考中…"，后续 delta 追加渲染
    while (!aborted) {
      const { done, value } = await reader.read()
      if (done) break
      buf += dec.decode(value, { stream: true })
      let nl
      while ((nl = buf.indexOf('\n\n')) >= 0) {
        const chunk = buf.slice(0, nl); buf = buf.slice(nl + 2)
        const line = chunk.split('\n').find((l) => l.startsWith('data:'))
        if (!line) continue
        let f
        try { f = JSON.parse(line.slice(5).trim()) } catch { continue }
        if (f.type === 'delta' && f.text) {
          bumpActivity()
          acc += f.text
          think.textContent = acc
          aiMsgs.scrollTop = aiMsgs.scrollHeight
        } else if (f.type === 'sid') {
          if (f.sessionId) aiChatSid = f.sessionId
        } else if (f.type === 'tool') {
          // Agent 正在执行工具：显示进度（区别于"思考中…"转圈）
          bumpActivity()
          if (f.evType === 'tool.completed') {
            think.textContent = acc || '思考中…'
          } else if (f.tool) {
            think.textContent = `⚙ 正在执行 ${f.tool}${f.preview ? ` · ${f.preview.slice(0, 40)}` : ''}…`
          }
          aiMsgs.scrollTop = aiMsgs.scrollHeight
        } else if (f.type === 'done') {
          bumpActivity()
          if (f.reply) { acc = f.reply; think.textContent = acc }
          if (f.sessionId) aiChatSid = f.sessionId
        } else if (f.type === 'error') {
          bumpActivity()
          acc = `（对话失败：${f.error || '未知错误'}）`
          think.textContent = acc
        }
      }
    }
    think.textContent = acc || '（无回复）'
  } catch (e) {
    // 用户 Stop：保留已生成内容；否则报通信失败
    if (aborted) { think.textContent = acc || '（已停止）' }
    else { think.remove(); addAiMsg('ai', '（与 Hermes 通信失败）') }
  } finally {
    clearInterval(thinkTimer)
    aiBusy = false
    aiStopFn = null
    setAiSendBtn(false)
    aiSendBtn.onclick = aiSend
    // 队列：当前轮结束后自动发送下一条排队消息（发送前移除"已排队"提示气泡）
    if (aiQueue.length) {
      const next = aiQueue.shift()
      setTimeout(() => {
        if (next.el) next.el.remove()  // 自动隐藏排队提示
        aiInput.value = next.text
        aiSend()
      }, 100)
    }
  }
  if (selN || selVulnIds.size) clearAiSel()  // 发送后清空选择（流量+漏洞）
}
aiSendBtn.onclick = aiSend
aiInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') aiSend() })

// ---- 状态栏（footer HERMES AGENT 实时状态） ----
async function refreshStatus() {
  try {
    const st = await (await fetch(`${API}/api/status`)).json()
    const el = document.getElementById('hermesAgent')
    const stEl = document.getElementById('hermesState')
    if (st.hermes === 'active') {
      stEl.textContent = 'ACTIVE'
      el.style.color = '#5b6b7d'  // 与 @2026 文案同色；仅异常才红色
    } else {
      stEl.textContent = 'OFFLINE'
      el.style.color = '#f76b6b'  // 异常红色
    }
  } catch {
    const el = document.getElementById('hermesAgent')
    if (el) { document.getElementById('hermesState').textContent = 'OFFLINE'; el.style.color = '#f76b6b' }
  }
}
setInterval(refreshStatus, 2000)
refreshStatus()

// ---- Site Map（Burp Target 树风格：Host → 路径段层级，叶子=请求记录） ----
let smCache = []       // 全量 flows（limit 5000）
let smExpanded = new Set()  // 展开的节点 key（host|/seg/seg）
let smSelHost = null
let smSelPrefix = null  // 当前选中路径前缀（null=显示 host 全部）
let smTimer = null      // Site Map 激活时的实时刷新定时器
function buildSmTree() {
  // host → { flows, pathTree: {seg: {count, child: {...}, flows: []}} }
  const hosts = {}
  for (const f of smCache) {
    let h
    try { h = new URL(f.url).host } catch { continue }
    if (!hosts[h]) hosts[h] = { flows: [], pathTree: {} }
    hosts[h].flows.push(f)
    const segs = (new URL(f.url).pathname || '/').split('/').filter(Boolean)
    let node = hosts[h].pathTree
    for (const s of segs) {
      if (!node[s]) node[s] = { count: 0, child: {}, flows: [] }
      node[s].count++
      node[s].flows.push(f)
      node = node[s].child
    }
  }
  return hosts
}
function renderSmTree() {
  const hosts = buildSmTree()
  const el = document.getElementById('smTree')
  const esc = (s) => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  // 节点下流量的最高漏洞等级（与 HTTP History 图标/颜色一致：BUG 图标 + 等级色）
  const nodeVulnLevel = (flows) => {
    const order = { high: 3, medium: 2, low: 1, info: 0 }
    let best = null
    for (const f of flows) {
      const an = (window.__anStatus || {})[f.id]
      if (an?.state === 'done' && an.vuln && (!best || order[an.level] > order[best])) best = an.level
    }
    return best
  }
  // 树节点漏洞等级：自身流量 + 递归聚合子树（/tmp/ 下高危+中危 → /tmp/ 显示高危；根节点同样递归到最高）
  const treeVulnLevel = (n) => {
    const order = { high: 3, medium: 2, low: 1, info: 0 }
    let best = nodeVulnLevel(n.flows)
    for (const c of Object.values(n.child)) {
      const sub = treeVulnLevel(c)
      if (sub && (!best || order[sub] > order[best])) best = sub
    }
    return best
  }
  const renderPath = (node, prefix, depth, host) => {
    let html = ''
    for (const [seg, n] of Object.entries(node)) {
      const key = prefix + '/' + seg
      const open = smExpanded.has(key)
      const hasChild = Object.keys(n.child).length > 0
      const selBg = smSelPrefix === key ? 'background:#3a2d1e' : ''
      const lv = treeVulnLevel(n)  // 整条链聚合：叶子=自身漏洞，父节点=子树最高等级（根到子节点全程标识）
      const icon = lv ? `<span style="vertical-align:-2px">${bugSvg(AN_LEVEL_COLOR[lv])}</span> ` : ''
      html += `<div style="padding:2px 4px 2px ${depth * 14 + 8}px;cursor:pointer;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:#8b98a8;border-radius:2px${selBg}" class="sm-path" data-key="${esc(key)}" data-host="${esc(host)}" data-count="${n.count}">${icon}${hasChild ? (open ? '▾ ' : '▸ ') : '· '}<span style="color:#d8e0ea">/${esc(seg)}</span> <span style="color:#66788a">(${n.count})</span></div>`
      if (open) html += renderPath(n.child, key, depth + 1, host)
    }
    return html
  }
  el.innerHTML = Object.entries(hosts).map(([host, h]) => {
    const open = smExpanded.has('HOST|' + host)
    const bg = smSelHost === host ? 'background:#1e3a5f' : ''
    const hostLv = treeVulnLevel({ flows: h.flows, child: h.pathTree })  // host 根节点：整站聚合最高等级
    const hostIcon = hostLv ? `<span style="vertical-align:-2px">${bugSvg(AN_LEVEL_COLOR[hostLv])}</span> ` : ''
    return `<div style="padding:3px 6px;cursor:pointer;font-weight:600;color:#4fc3f7;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;border-radius:2px${bg}" class="sm-host" data-host="${esc(host)}" data-count="${h.flows.length}">${hostIcon}${open ? '▾' : '▸'} 🌐 ${esc(host)} <span style="color:#66788a;font-weight:400">(${h.flows.length})</span></div>` +
      (open ? `<div style="border-left:1px solid #262c36;margin-left:10px">${renderPath(h.pathTree, '', 1, host)}</div>` : '')
  }).join('') || '<div style="padding:10px;color:#66788a">暂无流量</div>'
  el.querySelectorAll('.sm-host').forEach((n) => {
    n.onclick = (e) => {
      const host = n.dataset.host
      const key = 'HOST|' + host
      if (e.ctrlKey || e.metaKey || e.shiftKey) {
        // 多选：选中该 host 下全部流量（父节点聚合，可发 Agent——不受假删除影响）
        const sub = smCache.filter((f) => { try { return new URL(f.url).host === host } catch { return false } })
        const any = sub.some((f) => !selFlowIds.has(f.id))
        for (const f of sub) { if (any) { selFlowIds.add(f.id); smSelFlowIds.add(f.id) } else { selFlowIds.delete(f.id); smSelFlowIds.delete(f.id) } }
        lastSelFlowId = sub.length ? sub[0].id : null
        renderAiSelBar()
        return
      }
      if (smExpanded.has(key)) smExpanded.delete(key)
      else smExpanded.add(key)
      smSelHost = host
      smSelPrefix = null
      renderSmTree()
      renderSmTable(host, null)
    }
  })
  el.querySelectorAll('.sm-path').forEach((n) => {
    n.onclick = (e) => {
      const key = n.dataset.key
      if (e.ctrlKey || e.metaKey || e.shiftKey) {
        // 多选：选中该路径下全部叶子流量（父节点聚合 → 所有子节点流量，可发 Agent）
        const host = n.dataset.host
        const sub = smCache.filter((f) => { try { const u = new URL(f.url); return u.host === host && u.pathname.startsWith(key) } catch { return false } })
        const any = sub.some((f) => !selFlowIds.has(f.id))
        for (const f of sub) { if (any) { selFlowIds.add(f.id); smSelFlowIds.add(f.id) } else { selFlowIds.delete(f.id); smSelFlowIds.delete(f.id) } }
        lastSelFlowId = sub.length ? sub[0].id : null
        renderAiSelBar()
        return
      }
      if (smExpanded.has(key)) smExpanded.delete(key)
      else smExpanded.add(key)
      smSelPrefix = key
      renderSmTree()
      renderSmTable(smSelHost, key)  // 点击枝叶：右侧只显示该路径前缀下的流量
    }
  })
}
function renderSmTable(host, prefix) {
  const body = document.getElementById('smBody')
  const title = document.getElementById('smTitle')
  const flows = smCache.filter((f) => {
    try {
      const u = new URL(f.url)
      if (u.host !== host) return false
      if (prefix) return u.pathname.startsWith(prefix)
      return true
    } catch { return false }
  })
  title.textContent = `${host}${prefix ? prefix : ''} — ${flows.length} 条请求`
  body.innerHTML = flows.slice().reverse().map((f) =>
    `<tr style="cursor:pointer" data-id="${f.id}" data-method="${esc(f.method)}" data-url="${esc(f.url)}">
      <td style="padding:3px 8px;color:#66788a">${f.id}</td>
      <td style="padding:3px 8px" class="src-${f.source ?? 'proxy'}">${esc(f.method)}</td>
      <td style="padding:3px 8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;max-width:0">${esc(f.url)}</td>
      <td style="padding:3px 8px" class="${f.status >= 400 || f.status === 0 ? 'status-err' : 'status-ok'}">${f.status}</td>
      <td style="padding:3px 8px;color:#8b98a8">${f.bytes}</td>
    </tr>`).join('')
  body.querySelectorAll('tr').forEach((tr) => {
    const fid = Number(tr.dataset.id)
    if (selFlowIds.has(fid)) tr.style.background = '#1e3a5f'  // 已选中高亮（共享选中集）
    tr.onclick = (e) => {
      if (e.ctrlKey || e.metaKey || e.shiftKey) {
        // 多选（与流量表一致）：选中该条流量 → 可发给 Agent（站点地图选中不受假删除影响）
        if (selFlowIds.has(fid)) { selFlowIds.delete(fid); smSelFlowIds.delete(fid) } else { selFlowIds.add(fid); smSelFlowIds.add(fid); lastSelFlowId = fid }
        tr.style.background = selFlowIds.has(fid) ? '#1e3a5f' : ''
        renderAiSelBar()
        return
      }
      detailStates.sitemap = { id: fid, method: tr.dataset.method, url: tr.dataset.url }
      showFlowDetail(fid, tr.dataset.method, tr.dataset.url)  // flowDetail 全局化：当前面板下方直接显示，不跳转
    }
  })
}
async function refreshSitemap() {
  try {
    const j = await (await fetch(`${API}/api/flows?limit=5000`)).json()
    smCache = (j.items || []).filter((f) => !f.builtin && !f.skipped)  // 浏览器自带/错误码流量不进站点地图
    if (!smSelHost && smCache.length) { try { smSelHost = new URL(smCache[0].url).host } catch {} }
    renderSmTree()
    if (smSelHost) renderSmTable(smSelHost, smSelPrefix)  // 保持当前路径筛选
  } catch { /* 拉取失败忽略 */ }
}
const fviews = { intercept: document.getElementById('fview-intercept'), http: document.getElementById('fview-http'), repeater: document.getElementById('fview-repeater'), ws: document.getElementById('fview-ws') }
document.querySelectorAll('.ftab').forEach((b) => {
  b.onclick = () => {
    document.querySelectorAll('.ftab').forEach((x) => x.classList.remove('active'))
    b.classList.add('active')
    for (const [k, el] of Object.entries(fviews)) el.style.display = k === b.dataset.ftab ? 'flex' : 'none'
    intTabActive = b.dataset.ftab === 'intercept'
    if (b.dataset.ftab === 'ws') loadWsFlows()
    if (b.dataset.ftab === 'intercept') refreshIntercept()
    // 请求/响应详情：仅在 HTTP 视图显示；切到其他视图隐藏，切回恢复（dataset 标记 O(1) 判断，不读 innerHTML）
    if (b.dataset.ftab !== 'http') flowDetail.style.display = 'none'
    else if (flowDetail.dataset.hasContent) flowDetail.style.display = 'flex'
    if (document.querySelector('nav button.active')?.dataset.panel === 'flows') setAppTitle('flows')  // 流量面板子页切换 → 标题更新
  }
})
// Intercept：Intercept/Forward/Drop 三按钮 + 拦截流量表格（选中行 → Forward/Drop 高亮）
const intBody = document.getElementById('intBody')
const intToggle = document.getElementById('intToggle')
const btnIntForward = document.getElementById('btnIntForward')
const btnIntDrop = document.getElementById('btnIntDrop')
let intEnabled = false
let intSelected = new Set()
let intTabActive = false
// ponytail: initFlowResizers 调用移到 loadSettings 定义后（SKEY const TDZ 会中断 app.js）
// 拦截队列实时轮询（Intercept tab 激活时 1s）
setInterval(() => { if (intTabActive) refreshIntercept() }, 1000)

// ---- Agent 分析状态列：轮询队列状态渲染图标（转圈=分析中 / ✓=无漏洞 / BUG 图标=有漏洞，描边色=等级） ----
// 分析消费由后端驱动（本地 Hermes CLI 同一会话逐个分析），renderer 仅轮询状态渲染
const AN_LEVEL_COLOR = { high: '#f76b6b', medium: '#f7a35c', low: '#f7e05c', info: '#8b98a8' }
// Lucide bug 图标（iconfont 同款 BUG 象征：圆身+六腿+触角），描边颜色标识漏洞等级
function bugSvg(color) {
  return `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="${color}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" title="发现漏洞"><path d="m8 2 1.88 1.88"/><path d="M14.12 3.88 16 2"/><path d="M9 7.13v-1a3.003 3.003 0 1 1 6 0v1"/><path d="M12 20c-3.3 0-6-2.7-6-6v-3a4 4 0 0 1 4-4h4a4 4 0 0 1 4 4v3c0 3.3-2.7 6-6 6"/><path d="M12 20v-9"/><path d="M6.53 9C4.6 8.8 3 7.1 3 5"/><path d="M6 13H2"/><path d="M3 21c0-2.1 1.7-3.9 3.8-4"/><path d="M20.97 5c0 2.1-1.6 3.8-3.5 4"/><path d="M22 13h-4"/><path d="M17.2 17c2.1.1 3.8 1.9 3.8 4"/></svg>`
}
// Lucide check-circle（与 bug 同描边风格），绿色 = 无漏洞
function checkSvg() {
  return '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#5cd67a" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>'
}
// Lucide corner-up-right：拐弯跳过箭头（404/502 等错误码流量跳过 Agent 的图标）
function skipSvg() {
  return '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#8b98a8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 14 20 9 15 4"/><path d="M4 20v-7a4 4 0 0 1 4-4h12"/></svg>'
}
setInterval(async () => {
  try {
    const j = await (await fetch(`${API}/api/analyze/status`)).json()
    window.__anStatus = j.items || {}
    window.__anSensitive = {}
    for (const [id, s] of Object.entries(j.items || {})) {
      if (s.sensitive?.length) window.__anSensitive[id] = s.sensitive
      if (s.state === 'done' && window.__fdFlowId === Number(id)) applyFdHighlight(s)  // 详情打开中：分析完成即刷等级色高亮
      const td = document.querySelector(`.an-col[data-fid="${id}"]`)
      if (!td) continue
      // 缓存 key 含 skipped/builtin 标记：避免 done+skipped 与 done 普通绿勾共用缓存导致旧图标残留
      const stKey = s.state + (s.vuln ? 'v' : '') + (s.level || '') + (s.skipped || s.builtin ? 's' : '')
      if (td.dataset.state === stKey) continue
      td.dataset.state = stKey
      td.innerHTML = s.state === 'queued' || s.state === 'analyzing'
        ? '<span class="an-spinner" title="Agent 分析中…"></span>'
        : s.skipped || s.builtin
          ? skipSvg()  // 黑名单/错误码流量统一跳过 ICON（builtin 不再绿勾）
          : s.vuln
            ? bugSvg(AN_LEVEL_COLOR[s.level] || '#8b98a8')
            : checkSvg()
    }
  } catch { /* 分析状态拉取失败忽略 */ }
}, 1000)
function intBtnState() {
  const has = intSelected.size > 0
  btnIntForward.style.background = has ? '#1e3a5f' : '#232b36'
  btnIntForward.style.color = has ? '#4fc3f7' : '#8b98a8'
  btnIntDrop.style.background = has ? '#3a1e1e' : '#232b36'
  btnIntDrop.style.color = has ? '#ef5350' : '#8b98a8'
  btnIntForward.disabled = !has
  btnIntDrop.disabled = !has
}
async function refreshIntercept() {
  const r = await fetch(`${API}/api/intercept/state`).then((x) => x.json())
  intEnabled = !!r.enabled
  intToggle.textContent = intEnabled ? 'Intercept on' : 'Intercept off'
  intToggle.style.color = intEnabled ? '#4fc3f7' : '#8b98a8'
  intBody.innerHTML = ''
  const prevSel = new Set(intSelected)
  intSelected = new Set()
  for (const i of r.queue) {
    const tr = document.createElement('tr')
    tr.dataset.int = i.id
    tr.style.cursor = 'pointer'
    const d = new Date(i.ts)
    const hhmmss = [d.getHours(), d.getMinutes(), d.getSeconds()].map((n) => String(n).padStart(2, '0')).join(':')
    tr.innerHTML = `<td>${hhmmss}</td><td>Request</td><td style="color:#4fc3f7">→</td><td>${i.method}</td><td title="${i.url}">${i.url}</td><td>-</td><td>-</td>`
    // 轮询刷新保留选中态（鼠标移开/刷新不丢焦点）
    if (prevSel.has(i.id)) {
      tr.classList.add('int-sel')
      intSelected.add(i.id)
    }
    tr.onclick = () => {
      tr.classList.toggle('int-sel')
      if (intSelected.has(i.id)) intSelected.delete(i.id); else intSelected.add(i.id)
      intBtnState()
    }
    intBody.appendChild(tr)
  }
  intBtnState()
}
intToggle.onclick = async () => {
  await fetch(`${API}/api/intercept/state`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ enabled: !intEnabled }) })
  refreshIntercept()
}
btnIntForward.onclick = async () => {
  for (const id of intSelected) await fetch(`${API}/api/intercept/forward`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id }) })
  refreshIntercept()
}
btnIntDrop.onclick = async () => {
  for (const id of intSelected) await fetch(`${API}/api/intercept/drop`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ id }) })
  refreshIntercept()
}
// WebSockets History
const wsBody = document.getElementById('wsBody')
async function loadWsFlows() {
  const r = await fetch(`${API}/api/wsflows`).then((x) => x.json())
  wsBody.innerHTML = ''
  for (const f of r.items) {
    const tr = document.createElement('tr')
    const t = new Date(f.ts).toLocaleTimeString()
    const dir = f.direction === 'sent' ? '→' : '←'
    tr.innerHTML = `<td>${t}</td><td style="color:${f.direction === 'sent' ? '#4fc3f7' : '#ffb74d'}">${dir}</td><td>${f.length}</td><td title="${f.payload.replace(/"/g, '&quot;')}">${(f.payload || '').replace(/</g, '&lt;').slice(0, 200)}</td>`
    wsBody.appendChild(tr)
  }
}

// ---- 流量详情（点击行查看 MITM 全量报文：请求/响应头+体，JSON 格式化） ----
const flowDetail = document.getElementById('flowDetail')
function fmtBody(s) {
  if (!s) return '(空)'
  if (s.length > 200000) return s.slice(0, 200000) + '\n…(截断)'
  try { return JSON.stringify(JSON.parse(s), null, 2) } catch { return s }
}
function fmtHeaders(h, raw) {
  if (raw && raw.length) return raw.join('\n')
  if (!h || !Object.keys(h).length) return '(无)'
  return Object.entries(h).map(([k, v]) => `${k}: ${v}`).join('\n')
}
async function showFlowDetail(id, method, url) {
  const r = await fetch(`${API}/api/flows/${id}/detail`)
  if (!r.ok) { flowDetail.style.display = 'none'; delete flowDetail.dataset.hasContent; return }
  const d = await r.json()
  window.__fdDetail = { ...d, method, url }
  window.__fdFlowId = id
  document.getElementById('fdTitle').textContent = `${method} ${url}`
  window.__fdRaw = { req: `${d.reqLine || `${method} ${url}`}\n${fmtHeaders(d.reqHeaders, d.reqRawHeaders)}\n\n${fmtBody(d.reqBody)}`, res: `${d.resLine || ''}\n${fmtHeaders(d.resHeaders, d.resRawHeaders)}\n\n${fmtBody(d.resBody)}` }
  renderFdPane('req', '')
  renderFdPane('res', '')
  renderFdMarks('req', id)
  renderFdMarks('res', id)
  document.getElementById('fdReqSearch').value = ''
  document.getElementById('fdResSearch').value = ''
  applyFdHighlight((window.__anStatus || {})[id])
  flowDetail.dataset.hasContent = '1'  // 详情有内容标记（fview 切换恢复用，避免读 innerHTML 卡顿）
  flowDetail.style.display = 'flex'
}
// ---- 数据包按 Agent 分析结果高亮（颜色与漏洞列表 LEVEL_COLOR 一致） ----
function applyFdHighlight(an) {
  const color = AN_LEVEL_COLOR[an?.level] || null
  const vuln = an?.state === 'done' && !!an?.vuln
  for (const pre of [document.getElementById('fdReq'), document.getElementById('fdRes')]) {
    pre.style.borderColor = vuln && color ? color + '99' : '#262c36'
    pre.style.background = vuln && color ? color + '1f' : '#1c222c'
  }
}
// ---- MarkInfo（Hea 风格）：Agent 提取的敏感信息横向 chips，点击高亮正文 ----
const MARK_COLORS = { 'API Key': '#f76b6b', 'Bearer Token': '#4fc3f7', Password: '#f7a35c', Secret: '#f7e05c', Token: '#4fc3f7', Cookie: '#b388ff', Email: '#ce93d8', Phone: '#80cbc4', 'ID Card': '#ffb74d', 'Bank Card': '#ff8a65', 'Private Key': '#ef5350', Authorization: '#4fc3f7', 'Nday API': '#ff5252', 'Nday JS': '#ff7043', 'Nday 组件': '#ff5252', Username: '#8b98a8' }
const markColor = (t) => MARK_COLORS[t] || '#8b98a8'
function renderFdMarks(side, flowId) {
  const el = document.getElementById(side === 'req' ? 'fdMarkReq' : 'fdMarkRes')
  const sens = (window.__anSensitive && window.__anSensitive[flowId]) || []
  if (!sens.length) { el.style.display = 'none'; el.innerHTML = ''; return }
  el.style.display = 'flex'
  el.innerHTML = '<span style="font-size:10px;color:#66788a;line-height:18px">敏感信息：</span>' + sens.map((s) =>
    `<span data-mark="${esc(s.value)}" style="background:${markColor(s.type)}22;border:1px solid ${markColor(s.type)}88;color:${markColor(s.type)};border-radius:3px;padding:1px 6px;font-size:10px;cursor:pointer;line-height:16px;flex-shrink:0">${esc(s.type)}: ${esc(s.value.length > 24 ? s.value.slice(0, 24) + '…' : s.value)}</span>`
  ).join('')
  el.querySelectorAll('[data-mark]').forEach((chip) => {
    chip.onclick = () => {
      const q = chip.dataset.mark
      const box = side === 'req' ? document.getElementById('fdReq') : document.getElementById('fdRes')
      renderFdPane(side, '', q)  // 敏感值高亮（优先于搜索）
      box.scrollTop = 0
    }
  })
}
// ---- 详情窗格渲染（搜索/标记高亮） ----
function renderFdPane(side, query, markVal) {
  const pre = document.getElementById(side === 'req' ? 'fdReq' : 'fdRes')
  const raw = window.__fdRaw[side]
  let html = esc(raw)
  let n = 0
  if (markVal) {
    html = html.split(esc(markVal)).join('<mark style="background:#f76b6b55;color:#fff;border-radius:2px">' + esc(markVal) + '</mark>')
    n = raw.split(markVal).length - 1
    document.getElementById(side === 'req' ? 'fdReqCount' : 'fdResCount').textContent = n ? `${n} 处` : ''
  } else if (query) {
    const re = new RegExp(esc(query).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi')
    html = raw.replace(re, (m) => { n++; return `<mark style="background:#f7e05c44;color:#fff;border-radius:2px">${esc(m)}</mark>` })
    document.getElementById(side === 'req' ? 'fdReqCount' : 'fdResCount').textContent = n ? `${n} 处` : '无'
  } else {
    document.getElementById(side === 'req' ? 'fdReqCount' : 'fdResCount').textContent = ''
  }
  pre.innerHTML = html
}
document.getElementById('fdReqSearch').addEventListener('input', (e) => renderFdPane('req', e.target.value.trim()))
document.getElementById('fdResSearch').addEventListener('input', (e) => renderFdPane('res', e.target.value.trim()))
document.getElementById('btnFdClose').onclick = () => {
  flowDetail.style.display = 'none'
  const cur = document.querySelector('nav button.active')?.dataset.panel
  if (cur) delete detailStates[cur]  // 关闭 = 清当前面板的详情状态（其他面板保留）
}
// 拖动详情窗口顶部调整请求/响应窗口高度（向上拖增大，范围 120px~85%）
document.getElementById('fdResize').addEventListener('mousedown', (e) => {
  e.preventDefault()
  const startY = e.clientY
  const startH = flowDetail.getBoundingClientRect().height
  const parent = flowDetail.parentElement.getBoundingClientRect().height
  const onMove = (ev) => {
    const h = Math.min(Math.max(startH + (startY - ev.clientY), 120), parent * 0.85)
    flowDetail.style.height = h + 'px'
  }
  const onUp = () => {
    document.removeEventListener('mousemove', onMove)
    document.removeEventListener('mouseup', onUp)
  }
  document.addEventListener('mousemove', onMove)
  document.addEventListener('mouseup', onUp)
})

// ---- Repeater（重发器）：Burp 风格多标签页，协议自动识别（ws:// 首行 → WebSocket） ----
const repReq = document.getElementById('repReq')
const repRes = document.getElementById('repRes')
const repStatus = document.getElementById('repStatus')
const repTabsEl = document.getElementById('repTabs')
let repTabs = []        // { id, title, req, res, status }
let repTabSeq = 0
let curRepTab = null
function repTabTitle(reqText) {
  const first = (reqText || '').split('\n')[0].trim()
  if (!first) return '未命名'
  return first.length > 34 ? first.slice(0, 34) + '…' : first
}
function repSaveCur() {
  if (curRepTab == null) return
  const t = repTabs.find((x) => x.id === curRepTab)
  if (t) { t.req = repReq.value; t.res = repRes.textContent; t.status = repStatus.textContent }
}
function repSwitch(id) {
  repSaveCur()
  curRepTab = id
  const t = repTabs.find((x) => x.id === id)
  if (!t) return
  repReq.value = t.req
  repRes.textContent = t.res
  repStatus.textContent = t.status
  document.querySelectorAll('#repTabs .rep-tab').forEach((el) => el.classList.toggle('active', Number(el.dataset.id) === id))
}
function repRenderTabs() {
  repTabsEl.innerHTML = ''
  for (const t of repTabs) {
    const el = document.createElement('button')
    el.className = 'rep-tab' + (t.id === curRepTab ? ' active' : '')
    el.dataset.id = t.id
    el.style.cssText = 'background:#232b36;border:1px solid #2c3542;color:#8b98a8;cursor:pointer;padding:2px 8px;font-size:11px;white-space:nowrap'
    el.innerHTML = `${t.title} <span class="rep-x" style="color:#66788a;margin-left:4px">✕</span>`
    el.onclick = (e) => {
      if (e.target.classList.contains('rep-x')) { repCloseTab(t.id); return }
      repSwitch(t.id)
    }
    // 双击重命名（内联 input 继承按钮宽度，Enter/失焦提交，Esc 取消）
    el.ondblclick = (e) => {
      e.stopPropagation()
      const w = el.getBoundingClientRect().width
      el.innerHTML = ''
      const inp = document.createElement('input')
      inp.value = t.title
      inp.style.cssText = `width:${Math.max(w - 6, 40)}px;background:#1c222c;border:1px solid #4fc3f7;color:#d8e0ea;font-size:11px;padding:1px 4px`
      const commit = () => { t.title = (inp.value || '').trim() || t.title; repRenderTabs() }
      inp.onblur = commit
      inp.onkeydown = (ev) => { if (ev.key === 'Enter') commit(); else if (ev.key === 'Escape') repRenderTabs() }
      el.appendChild(inp)
      inp.focus()
      inp.select()
    }
    repTabsEl.appendChild(el)
  }
}
function repNewTab(title, reqText) {
  const id = ++repTabSeq
  repTabs.push({ id, title: title || '未命名', req: reqText || '', res: '', status: '' })
  repRenderTabs()
  repSwitch(id)
}
function repCloseTab(id) {
  const i = repTabs.findIndex((x) => x.id === id)
  if (i < 0) return
  repTabs.splice(i, 1)
  if (repTabs.length === 0) repNewTab()
  repRenderTabs()
  repSwitch(curRepTab === id ? repTabs[repTabs.length - 1].id : curRepTab)
}
document.getElementById('btnRepNew').onclick = () => repNewTab()
repNewTab()
document.getElementById('btnRepSend').onclick = async () => {
  repStatus.textContent = '发送中…'
  try {
    const r = await fetch(`${API}/api/repeater/send`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ raw: repReq.value }) }).then((x) => x.json())
    if (!r.ok) { repStatus.textContent = '错误: ' + (r.error || '未知'); return }
    repRes.textContent = `${r.statusLine}\n${r.headers.join('\n')}\n\n${r.body}`
    repStatus.textContent = `${r.statusLine} | 响应头 ${r.headers.length} 行`
    repSaveCur()
    const t = repTabs.find((x) => x.id === curRepTab)
    if (t) t.title = repTabTitle(repReq.value)
    repRenderTabs()
  } catch (e) { repStatus.textContent = '错误: ' + e.message }
}
// 详情窗口 → Repeater：新建标签页带入请求报文并切到 Repeater 页
document.getElementById('btnFdRep').onclick = () => {
  const d = window.__fdDetail
  if (!d) return
  // 绝对 URL（含 https 协议，repeater 据此走 HTTPS 分支）
  const reqText = `${d.method || 'GET'} ${d.url} HTTP/1.1\n${(d.reqRawHeaders || []).join('\n')}\n\n${d.reqBody || ''}`
  repNewTab(repTabTitle(reqText), reqText)
  document.querySelectorAll('.ftab').forEach((x) => x.classList.remove('active'))
  document.querySelector('.ftab[data-ftab="repeater"]').classList.add('active')
  for (const [k, el] of Object.entries(fviews)) el.style.display = k === 'repeater' ? 'flex' : 'none'
}
// ---- 右键菜单 + 添加漏洞弹窗（从流量表条目带出完整请求/响应包） ----
const ctxMenu = document.getElementById('ctxMenu')
const vulnModal = document.getElementById('vulnModal')
let ctxFlow = null
document.addEventListener('click', () => { ctxMenu.style.display = 'none' })
document.getElementById('ctxAddVuln').onclick = async (e) => {
  e.stopPropagation()
  ctxMenu.style.display = 'none'
  if (ctxFlow == null) return
  const d = await (await fetch(`${API}/api/flows/${ctxFlow.id}/detail`)).json()
  document.getElementById('mvName').value = ''
  document.getElementById('mvLevel').value = 'info'
  document.getElementById('mvCvss').value = ''
  document.getElementById('mvDesc').value = ''
  document.getElementById('mvReq').value = `${d.reqLine || ''}\n${(d.reqRawHeaders || []).join('\n')}\n\n${d.reqBody || ''}`
  document.getElementById('mvRes').value = `${d.resLine || ''}\n${(d.resRawHeaders || []).join('\n')}\n\n${d.resBody || ''}`
  vulnModal.style.display = 'flex'
}
const closeVulnModal = () => { vulnModal.style.display = 'none' }
// 右键菜单：Send to Repeater（当前流量完整请求报文 → 重发器新标签）
document.getElementById('ctxSendRep').onclick = async (e) => {
  e.stopPropagation()
  ctxMenu.style.display = 'none'
  if (ctxFlow == null) return
  const d = await (await fetch(`${API}/api/flows/${ctxFlow.id}/detail`)).json().catch(() => null)
  if (!d) return
  const raw = `${d.reqLine || ''}\n${(d.reqRawHeaders || []).join('\n')}\n\n${d.reqBody || ''}`
  newRepTab(`${ctxFlow.method} ${ctxFlow.url.split('?')[0]}`, raw)
  repSwitch(repTabs[repTabs.length - 1].id)
  document.querySelector('.ftab[data-ftab="repeater"]').click()
}
// 右键菜单：Delete Selected（前端假删除：仅 HTTP History 移除，站点地图/后端保留）
document.getElementById('ctxDelSel').onclick = async (e) => {
  e.stopPropagation()
  ctxMenu.style.display = 'none'
  if (!selFlowIds.size) return
  for (const id of selFlowIds) deletedFlowIds.add(id)
  selFlowIds.clear()
  lastSelFlowId = null
  renderAiSelBar()
  loadFlows()
}
// 右键菜单：Clear History（清空全部流量历史）
document.getElementById('ctxClear').onclick = async (e) => {
  e.stopPropagation()
  ctxMenu.style.display = 'none'
  await fetch(`${API}/api/flows/clear`, { method: 'POST' }).catch(() => {})
  selFlowIds.clear()
  lastSelFlowId = null
  renderAiSelBar()
  loadFlows()
  refreshSitemap()
}
document.getElementById('btnVulnModalClose').onclick = closeVulnModal
document.getElementById('btnVulnModalCancel').onclick = closeVulnModal
document.getElementById('btnVulnModalSave').onclick = async () => {
  const body = {
    name: document.getElementById('mvName').value || '未命名漏洞',
    level: document.getElementById('mvLevel').value,
    cvss: document.getElementById('mvCvss').value,
    uri: ctxFlow?.url || '',
    desc: document.getElementById('mvDesc').value,
    exploit: document.getElementById('mvExploit').value,
    reqRaw: document.getElementById('mvReq').value,
    resRaw: document.getElementById('mvRes').value,
  }
  const editId = vulnModal.dataset.editId
  if (editId) {
    await fetch(`${API}/api/vulns/detail?id=${editId}`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
    curVulnId = Number(editId)
  } else {
    await fetch(`${API}/api/vulns`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
  }
  closeVulnModal()
  loadVulns()
  if (curVulnId != null) showVuln(curVulnId)
}
// ---- 漏洞库（左 1/3 列表 + 右 2/3 文档视图；请求/响应代码段固定高；编辑/新建走弹窗） ----
const vulnListEl = document.getElementById('vulnList')
const vulnDoc = document.getElementById('vulnDoc')
let curVulnId = null
const selVulnIds = new Set()  // 漏洞多选（Ctrl/Shift，与流量表一致）→ 发 AI 完整文档
let lastSelVulnId = null
const LEVEL_COLOR = { high: '#f76b6b', medium: '#f7a35c', low: '#f7e05c', info: '#8b98a8' }
const LEVEL_LABEL = { high: '高', medium: '中', low: '低', info: '信息' }
function esc(s) { return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;') }
const STATUS_LABEL = { pending: '未确认', confirmed: '已确认', false: '误报' }
const STATUS_COLOR = { pending: '#f7a35c', confirmed: '#5cd67a', false: '#f76b6b' }
function hostOf(uri) { try { return new URL(uri).host } catch { return (uri || '').replace(/^https?:\/\//, '').split(/[/?#]/)[0] || '-' } }
function fmtTs(ts) { const d = new Date(ts || Date.now()); const p = (n) => String(n).padStart(2, '0'); return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}` }
function vulnDocHtml(v) {
  // 固定高代码段 + 工具栏（复制 / 发送至重发器 / AI分析利用），事件走 vulnDoc 委托
  const code = (t) => `<pre style="height:360px;margin:0;background:#0d1117;border:1px solid #262c36;border-radius:4px;padding:10px 12px;font-family:Consolas,monospace;font-size:12px;line-height:1.5;overflow:auto;white-space:pre;color:#c9d1d9">${esc(t) || '(无)'}</pre>`
  const bar = (label, kind, content) => `
    <div style="display:flex;align-items:center;gap:6px;margin:14px 0 6px">
      <h3 style="margin:0;font-size:15px;color:#d8e0ea;border-left:3px solid ${kind === 'req' ? '#f7a35c' : '#4fc3f7'};padding-left:8px;flex:1">${label}</h3>
      <button class="vp-btn" data-act="copy" data-kind="${kind}" data-content="${encodeURIComponent(content || '')}" style="background:#232b36;border:1px solid #2c3542;color:#8b98a8;cursor:pointer;padding:2px 10px;font-size:11px">复制</button>
      <button class="vp-btn" data-act="rep" data-kind="${kind}" data-content="${encodeURIComponent(content || '')}" style="background:#1e3a5f;border:1px solid #2c3542;color:#4fc3f7;cursor:pointer;padding:2px 10px;font-size:11px">发送至重发器</button>
      <button class="vp-btn" data-act="ai" data-kind="${kind}" data-content="${encodeURIComponent(content || '')}" style="background:#3a2d1e;border:1px solid #2c3542;color:#f7a35c;cursor:pointer;padding:2px 10px;font-size:11px">AI分析利用</button>
    </div>
    ${code(content)}
  `
  return `
    <h2 style="margin:0 0 10px;font-size:20px;color:#4fc3f7;border-bottom:1px solid #262c36;padding-bottom:8px">${esc(v.name)}</h2>
    <div style="display:flex;gap:16px;flex-wrap:wrap;margin-bottom:12px;font-size:12px;color:#8b98a8">
      <span>目标：<b style="color:#d8e0ea">${esc(hostOf(v.uri))}</b></span>
      <span>发现时间：<b style="color:#d8e0ea">${fmtTs(v.ts)}</b></span>
      <span>漏洞状态：<b style="color:${STATUS_COLOR[v.status] || '#f7a35c'}">${STATUS_LABEL[v.status] || '未确认'}</b></span>
    </div>
    <div style="display:flex;gap:16px;align-items:center;flex-wrap:wrap;margin-bottom:14px;font-size:12px;color:#8b98a8">
      <span>威胁等级：<b style="color:${LEVEL_COLOR[v.level] || '#8b98a8'}">${LEVEL_LABEL[v.level] || v.level}</b></span>
      <span>CVSS 评分：<b style="color:#d8e0ea">${esc(v.cvss) || '-'}</b></span>
      <span>触发 URI：<code style="color:#4fc3f7">${esc(v.uri) || '-'}</code></span>
      <button class="vp-btn" data-act="attack" data-kind="vuln" style="margin-left:auto;background:#3a2d1e;border:1px solid #2c3542;color:#f7a35c;cursor:pointer;padding:2px 12px;font-size:11px">Agent 渗透</button>
    </div>
    <h3 style="margin:14px 0 6px;font-size:15px;color:#d8e0ea;border-left:3px solid #4fc3f7;padding-left:8px">漏洞描述</h3>
    <p style="margin:0 0 6px;white-space:pre-wrap">${esc(v.desc) || '(无描述)'}</p>
    <h3 style="margin:14px 0 6px;font-size:15px;color:#d8e0ea;border-left:3px solid #f7a35c;padding-left:8px">利用信息</h3>
    <p style="margin:0 0 6px;white-space:pre-wrap;font-family:Consolas,monospace;font-size:12px;line-height:1.7">${esc(v.exploit) || '(未填写利用信息)'}</p>
    ${bar('原始请求包', 'req', v.reqRaw)}
    ${bar('原始响应包', 'res', v.resRaw)}
  `
}
// 工具栏事件委托：复制 / 发送至重发器 / AI分析利用
vulnDoc.addEventListener('click', async (e) => {
  const btn = e.target.closest('.vp-btn')
  if (!btn) return
  const content = decodeURIComponent(btn.dataset.content || '')
  const kind = btn.dataset.kind
  if (btn.dataset.act === 'copy') {
    await navigator.clipboard.writeText(content).catch(() => {})
    btn.textContent = '已复制'
    setTimeout(() => { btn.textContent = '复制' }, 1500)
  } else if (btn.dataset.act === 'rep') {
    newRepTab(kind === 'req' ? '漏洞请求' : '漏洞响应', content)
    repSwitch(repTabs[repTabs.length - 1].id)
    document.querySelector('.ftab[data-ftab="repeater"]').click()
  } else if (btn.dataset.act === 'attack') {
    // Agent 攻击：完整漏洞文档 → AI 助手；要求输出利用信息并写回（PUT /api/vulns/detail）
    const v = curVulnId != null ? await (await fetch(`${API}/api/vulns/detail?id=${curVulnId}`)).json() : null
    if (!v) return
    aiChatInput.value =
      `【漏洞利用任务】请作为渗透测试专家对以下漏洞进行进一步利用分析，并输出【利用信息】。\n\n` +
      `漏洞名称：${v.name}\n威胁等级：${LEVEL_LABEL[v.level] || v.level}\nCVSS 评分：${v.cvss || '-'}\n触发 URI：${v.uri || '-'}\n漏洞描述：${v.desc || '(无)'}\n\n` +
      `原始请求包：\n\`\`\`\n${v.reqRaw || '(无)'}\n\`\`\`\n原始响应包：\n\`\`\`\n${v.resRaw || '(无)'}\n\`\`\`\n\n` +
      `利用信息需包含：\n1. POC（可执行 payload / 命令）\n2. 利用请求包 / 响应包\n3. 分析过程（分步骤写明：第一步、第二步…）\n\n` +
      `分析完成后将【利用信息】文本写入漏洞记录（当前漏洞 id=${v.id}）：\ncurl -X PUT http://127.0.0.1:8877/api/vulns/detail?id=${v.id} -H 'content-type: application/json' -d '{"exploit":"第一步：…\\n第二步：…"}'`
    aiSend()
  }
})
async function loadVulns() {
  const st = vulnListEl.scrollTop
  const j = await (await fetch(`${API}/api/vulns`)).json()
  vulnListEl.innerHTML = ''
  for (const v of (j.items || []).slice().reverse()) {
    const el = document.createElement('div')
    const route = (v.uri || '').replace(/^https?:\/\/[^/]+/i, '')
    const lc = LEVEL_COLOR[v.level] || '#8b98a8'
    const confirmed = v.status === 'confirmed'
    const stLabel = STATUS_LABEL[v.status] || '未确认'
    const stColor = STATUS_COLOR[v.status] || '#f7a35c'
    const active = selVulnIds.has(v.id) || curVulnId === v.id  // 选中（发送集）或当前查看（默认高亮）
    el.style.cssText = `position:relative;padding:10px 12px;cursor:pointer;border:1px solid ${active ? lc + '80' : '#262c36'};border-radius:4px;background:${active ? lc + '0d' : 'transparent'};margin-bottom:6px;overflow:hidden`
    // 参考 Hermes 风格：名称+等级 badge / 路由 / ID+状态；激活项左侧色条
    el.innerHTML = `
      ${active ? `<div style="position:absolute;left:0;top:0;bottom:0;width:3px;background:${lc}"></div>` : ''}
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:6px">
        <span style="font-size:12px;font-weight:600;color:${active ? lc : '#d8e0ea'};overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(v.name)}</span>
        <span style="flex-shrink:0;font-size:10px;color:${lc};background:${lc}1a;border:1px solid ${lc}55;padding:0 5px;border-radius:3px">${LEVEL_LABEL[v.level] || v.level}</span>
      </div>
      <div style="margin-top:4px;font-size:11px;color:#8b98a8;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(route || v.uri || '-')}</div>
      <div style="display:flex;justify-content:space-between;align-items:center;margin-top:6px">
        <span style="font-size:10px;color:#66788a">ID: VULN-${v.id}</span>
        <span style="font-size:10px;color:${stColor}">${stLabel}</span>
      </div>
    `
    el.onclick = (e) => {
      if (e.ctrlKey || e.metaKey || e.shiftKey) {
        // 多选（与流量表一致）：Ctrl/Shift 切换选中，可发 AI 完整文档
        // 首次多选：默认查看的漏洞（curVulnId）一并加入发送集
        if (!selVulnIds.size && curVulnId != null) {
          selVulnIds.add(curVulnId)
          if (v.id === curVulnId) { loadVulns(); return }  // 点的是默认查看的：已在集内
        }
        if (selVulnIds.has(v.id)) selVulnIds.delete(v.id); else { selVulnIds.add(v.id); lastSelVulnId = v.id }
        loadVulns()
        return
      }
      selVulnIds.clear()  // 普通点击只查看详情（不发 Agent——与流量表一致）
      lastSelVulnId = null
      showVuln(v.id)
      loadVulns()  // 重绘使选中驱动高亮
    }
    el.classList.add('vuln-item')
    vulnListEl.appendChild(el)
  }
  // 默认选中第一条（最新漏洞）：进入面板且无选中时自动显示详情 + 高亮（curVulnId），但不进发送集（selVulnIds 空——Ctrl/Shift 明确选中才发 Agent）
  if (!selVulnIds.size && (j.items || []).length) {
    showVuln(j.items[j.items.length - 1].id)
  }
  vulnListEl.scrollTop = st
}
async function showVuln(id) {
  curVulnId = id
  const v = await (await fetch(`${API}/api/vulns/detail?id=${id}`)).json()
  vulnDoc.innerHTML = vulnDocHtml(v)
}
// 编辑：弹窗预填 → PUT
document.getElementById('btnVulnEdit').onclick = async () => {
  if (curVulnId == null) return
  const v = await (await fetch(`${API}/api/vulns/detail?id=${curVulnId}`)).json()
  document.getElementById('mvName').value = v.name || ''
  document.getElementById('mvLevel').value = v.level || 'info'
  document.getElementById('mvCvss').value = v.cvss || ''
  document.getElementById('mvDesc').value = v.desc || ''
  document.getElementById('mvExploit').value = v.exploit || ''
  document.getElementById('mvReq').value = v.reqRaw || ''
  document.getElementById('mvRes').value = v.resRaw || ''
  vulnModal.dataset.editId = curVulnId
  vulnModal.style.display = 'flex'
}
document.getElementById('btnVulnNew').onclick = async () => {
  curVulnId = null
  vulnDoc.innerHTML = '<p style="color:#66788a">新建漏洞中…填写后保存</p>'
  document.getElementById('mvName').value = ''
  document.getElementById('mvLevel').value = 'info'
  document.getElementById('mvCvss').value = ''
  document.getElementById('mvDesc').value = ''
  document.getElementById('mvExploit').value = ''
  document.getElementById('mvReq').value = ''
  document.getElementById('mvRes').value = ''
  delete vulnModal.dataset.editId
  vulnModal.style.display = 'flex'
  document.getElementById('mvName').focus()
}
document.getElementById('btnVulnDel').onclick = async () => {
  if (curVulnId == null) return
  if (!confirm('确认删除该漏洞记录？')) return
  await fetch(`${API}/api/vulns/detail?id=${curVulnId}`, { method: 'DELETE' })
  curVulnId = null
  vulnDoc.innerHTML = '<p style="color:#66788a">从左侧选择漏洞，或点「+ 新建漏洞」</p>'
  loadVulns()
}
loadVulns()
// ---- 流量（Burp 风格 11 列表头，固定列宽 + 可拖拽） ----
const flowsBody = document.getElementById('flowsBody')
function parseUrl(u) {
  try {
    const x = new URL(u)
    return { host: x.host, params: x.search.replace(/^\?/, ''), ext: (x.pathname.match(/\.([a-z0-9]+)$/i) || [])[1] || '' }
  } catch { return { host: '', params: '', ext: '' } }
}
function addFlowRow(f) {
  const { host, params, ext } = parseUrl(f.url)
  const tr = document.createElement('tr')
  tr.style.cursor = 'pointer'
  if (selFlowIds.has(f.id)) tr.classList.add('sel')  // 轮询重渲染后保持选中态
  tr.dataset.fid2 = String(f.id)
  tr.innerHTML = `<td class="an-col" data-fid="${f.id}"></td><td>${f.id}</td><td title="${host}">${host}</td>` +
    `<td class="src-${f.source ?? 'proxy'}">${f.method}</td><td title="${f.url}">${f.url}</td>` +
    `<td title="${params}">${params}</td><td></td>` +
    `<td class="${f.status >= 400 || f.status === 0 ? 'status-err' : 'status-ok'}">${f.status}</td>` +
    `<td>${f.bytes}</td><td></td><td>${ext}</td><td></td>`
  tr.onclick = (e) => {
    if (e.ctrlKey || e.metaKey) {
      // Ctrl：toggle 单行选中
      if (selFlowIds.has(f.id)) selFlowIds.delete(f.id)
      else selFlowIds.add(f.id)
      lastSelFlowId = f.id
      tr.classList.toggle('sel')
      renderAiSelBar()
      return
    }
    if (e.shiftKey && lastSelFlowId != null) {
      // Shift：从上次选中到当前行的范围选择（DOM 实时行序，含 SSE 增量新行）
      const ids = [...document.querySelectorAll('#flowTable tr')].map((tr) => Number(tr.dataset.fid2)).filter((x) => Number.isInteger(x))
      const a = ids.indexOf(lastSelFlowId)
      const b = ids.indexOf(f.id)
      if (a >= 0 && b >= 0) {
        for (const id of ids.slice(Math.min(a, b), Math.max(a, b) + 1)) selFlowIds.add(id)
        lastSelFlowId = f.id
        renderAiSelBar()
        document.querySelectorAll('#flowTable tr').forEach((tr) => tr.classList.toggle('sel', selFlowIds.has(Number(tr.dataset.fid2))))
      }
      return
    }
    // 无修饰：只显示详情，不选中（选中激活必须 Ctrl/Shift——普通点击不会把流量发给 Agent）
    detailStates.flows = { id: f.id, method: f.method, url: f.url }
    showFlowDetail(f.id, f.method, f.url)
  }
  // 右键：添加入漏洞库（弹窗带出完整请求/响应包）
  tr.oncontextmenu = (e) => {
    e.preventDefault()
    ctxFlow = f
    ctxMenu.style.display = 'block'
    ctxMenu.style.left = e.clientX + 'px'
    ctxMenu.style.top = e.clientY + 'px'
    // Delete Selected 仅在有条目选中时显示（假删除菜单项）
    document.getElementById('ctxDelSel').style.display = selFlowIds.size ? 'block' : 'none'
  }
  flowsBody.prepend(tr)
  while (flowsBody.children.length > 500) flowsBody.lastChild.remove()
}
// 列宽拖拽（宽度存 localStorage，用户可自定义）
function initFlowResizers(sel = '#flowHeadTable', key = 'flowCols') {
  const cols = document.querySelectorAll(`${sel} col`)
  const twin = sel === '#flowHeadTable' ? document.querySelectorAll('#flowTable col') : null
  const saved = (loadSettings()[key] || {})
  for (let i = 0; i < cols.length; i++) if (saved[i]) {
    cols[i].style.width = saved[i] + 'px'
    twin?.[i] && (twin[i].style.width = saved[i] + 'px')
  }
  document.querySelectorAll(`${sel} th .resizer`).forEach((rz, i) => {
    rz.addEventListener('mousedown', (e) => {
      e.preventDefault()
      const startX = e.clientX
      const startW = cols[i].getBoundingClientRect().width
      const onMove = (ev) => {
        const w = Math.max(30, startW + (ev.clientX - startX))
        cols[i].style.width = w + 'px'
        twin?.[i] && (twin[i].style.width = w + 'px')
      }
      const onUp = () => {
        document.removeEventListener('mousemove', onMove)
        document.removeEventListener('mouseup', onUp)
        const s = loadSettings()
        s[key] = { ...(s[key] || {}), [i]: cols[i].getBoundingClientRect().width }
        saveSettings({ [key]: s[key] })
      }
      document.addEventListener('mousemove', onMove)
      document.addEventListener('mouseup', onUp)
    })
  })
}
// 横向滚动同步表头（滚动条轨道从表头底部开始；表头随横向滚动平移）
document.querySelector('.flows-wrap').onscroll = (e) => {
  // 表头横向跟随表体滚动（scrollLeft 同步——transform 右移时表头会显示不全）
  document.getElementById('flowHeadWrap').scrollLeft = e.target.scrollLeft
}
async function loadFlows() {
  const j = await (await fetch(`${API}/api/flows?limit=100`)).json()
  flowsBody.innerHTML = ''
  j.items.slice().reverse().forEach((f) => { if (!deletedFlowIds.has(f.id)) addFlowRow(f) })  // 假删除过滤（站点地图不受影响）
}
loadFlows()
const es = new EventSource(`${API}/api/events`)
es.onmessage = (e) => {
  const f = JSON.parse(e.data)
  if (f.type === 'analyze-advice') { renderAdviceCard(f); return }  // 子 Agent 渗透意见 → 聊天框意见卡
  if (f.type === 'vuln-doc') {
    // 有漏洞成果：用成果卡替换原渗透建议卡（同 API 路径匹配；成果卡不做超时删除，常驻可点击查详情）
    const vpath = (f.vuln.uri || '').replace(/^https?:\/\/[^/]+/i, '')
    if (vpath) {
      for (const w of document.querySelectorAll('#aiChatMsgs [data-role="ai"]')) {
        if (w.textContent.includes('经 Hermes 分析') && w.textContent.includes(vpath.slice(0, 20))) { w.remove(); break }
      }
    }
    renderVulnDocCard(f.vuln)
    return
  }
  if (f.type === 'penetrate-done') {
    const t = [...aiTasks.values()].find((x) => x.slot === f.slot)
    if (t) {
      if (f.skipped) {
        // 子 Agent 判定该目标API渗透方式已进行过 → 自动取消：移除后台任务条，子 Agent 释放槽位继续流量分析
        aiTasks.delete(t.id)
        renderAiTasks()
        for (const w of document.querySelectorAll('#aiChatMsgs [data-role="ai"]')) {
          if (t.advice && w.textContent.includes(t.advice.slice(0, 20))) {
            const st = [...w.querySelectorAll('div')].find((d) => d.textContent.includes('已确认进行渗透') || d.textContent.includes('渗透执行中'))
            if (st) st.textContent = '该目标API渗透方式已进行过 自动跳过'
            // 已跳过卡（无后台任务）→ 30s 自动淡出移除
            setTimeout(() => { w.style.transition = 'opacity .5s'; w.style.opacity = '0'; setTimeout(() => w.remove(), 600) }, 30000)
            break
          }
        }
      } else {
        t.reply = f.reply || ''; t.status = 'done'; renderAiTasks()
      }
    }
    // 主聊天"回复子 Agent" / 子 Agent 沟通窗口：等待该 slot 结果（SSE 送达）→ 展示回复并恢复 UI
    const pend = pendingSubRuns.get(f.slot)
    if (pend) {
      pendingSubRuns.delete(f.slot)
      pend.show(f.skipped ? '该目标API渗透方式已进行过 自动跳过' : (f.reply || '（子 Agent 无响应）'))
    }
    return
  }
  if (f.method) addFlowRow(f)
}
// ---- 子 Agent 渗透成果（vulndoc）：写入漏洞库完成 → 聊天框简述卡片（高危 目标：XXX 名称 / 已同步记忆 / 点击查看漏洞列表详情） ----
function renderVulnDocCard(v) {
  const wrap = document.createElement('div')
  wrap.dataset.role = 'ai'
  wrap.style.cssText = 'background:#1e2a1e;border:1px solid #2c3542;border-radius:8px;padding:8px 10px;font-size:12px;line-height:1.6;cursor:pointer'
  wrap.title = '点击查看漏洞详情'
  const lv = { high: '高危', medium: '中危', low: '低危', info: '信息' }[v.level] || v.level
  const lc = { high: '#f76b6b', medium: '#f0b35c', low: '#e8d47a', info: '#8b98a8' }[v.level] || '#8b98a8'
  const target = hostOf(v.uri || '')
  wrap.innerHTML = `<div style="color:#d7dde4"><span style="color:${lc};font-weight:600">${lv}</span> 目标：${target || '未知'} <b>${v.name}</b></div><div style="margin-top:3px;color:#8b98a8;font-size:11px">已同步到主 Agent 记忆</div><div style="margin-top:3px;color:#4fc3f7;font-size:11px">点击查看漏洞详情</div>`
  wrap.onclick = () => { const b = document.querySelector('nav button[data-panel="vulns"]'); if (b) b.click(); showVuln(v.id); loadVulns() }  // 切面板 + 选中对应漏洞（详情 + 列表高亮）
  aiMsgs.appendChild(wrap)
  aiMsgs.scrollTop = aiMsgs.scrollHeight
  loadVulns()  // 漏洞面板刷新
  // 成果卡常驻（不做超时删除——用户可随时点击查看漏洞详情；被同 API 新成果替换时由替换逻辑移除）
}
// ---- 子 Agent 渗透意见卡（Hermes Agent 聊天框）：进行渗透 / 取消渗透 / 回复；60s 超时自动取消 ----
function renderAdviceCard(a) {
  // 同 API 意见卡去重：同路径的新意见替换旧卡（取消后再出现的重复意见不再堆积）
  const apiPath = (a.advice || '').match(/分析\s*(\S+?)\s*可进行/)?.[1]
  if (apiPath) {
    for (const w of document.querySelectorAll('#aiChatMsgs [data-role="ai"]')) {
      if (w.textContent.includes(`经 Hermes 分析 ${apiPath} 可进行`)) w.remove()
    }
  }
  const wrap = document.createElement('div')
  wrap.dataset.role = 'ai'
  wrap.style.cssText = 'background:#16212e;border:1px solid #2c3542;border-radius:8px;padding:8px 10px;font-size:12px;line-height:1.6;max-width:100%'
  const txt = document.createElement('div')
  txt.textContent = a.advice
  wrap.appendChild(txt)
  const row = document.createElement('div')
  row.style.cssText = 'display:flex;align-items:center;gap:8px;margin-top:8px'
  const go = document.createElement('button')
  go.style.cssText = 'flex:1;display:flex;align-items:center;justify-content:center;gap:6px;background:#1e3a2a;border:1px solid #2c3542;color:#5cd67a;cursor:pointer;padding:5px 0;border-radius:6px;font-size:12px'
  go.innerHTML = checkSvg() + '进行渗透'
  const cancel = document.createElement('button')
  cancel.style.cssText = 'flex:1;display:flex;align-items:center;justify-content:center;gap:6px;background:#3a2020;border:1px solid #2c3542;color:#f76b6b;cursor:pointer;padding:5px 0;border-radius:6px;font-size:12px'
  cancel.innerHTML = '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#f76b6b" stroke-width="2.4" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>取消渗透'
  const reply = document.createElement('button')
  reply.title = '回复该意见（回复内容发给主 Agent）'
  reply.style.cssText = 'width:34px;height:28px;display:flex;align-items:center;justify-content:center;background:#1e3a5f;border:1px solid #2c3542;color:#4fc3f7;cursor:pointer;border-radius:6px;flex-shrink:0'
  reply.innerHTML = skipSvg()
  row.appendChild(go)
  row.appendChild(cancel)
  row.appendChild(reply)
  wrap.appendChild(row)
  aiMsgs.appendChild(wrap)
  aiMsgs.scrollTop = aiMsgs.scrollHeight
  let done = false
  const closeCard = (txt2) => {
    if (done) return
    done = true
    clearTimeout(timer)
    row.style.display = 'none'
    const st = document.createElement('div')
    st.style.cssText = 'margin-top:6px;color:#8b98a8;font-size:11px'
    st.textContent = txt2
    wrap.appendChild(st)
  }
  const timer = setTimeout(() => { closeCard('⏱ 超时未确认，已自动取消渗透'); resumeSlot(); setTimeout(() => { wrap.style.transition = 'opacity .5s'; wrap.style.opacity = '0'; setTimeout(() => wrap.remove(), 600) }, 5000) }, 60000)  // 60s 自动取消 + 取消后 5s 自动隐藏
  // 卡片关闭/取消 → 通知后端恢复该子 Agent 流量分析（pendingAdviceSlots 释放）
  const resumeSlot = () => { const s = a.slot ?? 0; fetch(`${API}/api/advice/resume`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ slot: s }) }).catch(() => {}) }
  go.onclick = async () => {
    closeCard('✓ 已确认进行渗透，由对应子 Agent 执行中…')
    const m2 = a.advice.match(/分析\s*(\S+)\s*可进行\s*(.+?)\s*渗透/)
    const label = m2 ? `${m2[1]} ${m2[2]} 渗透` : a.advice.replace(/^经 Hermes 分析 /, '').slice(0, 26)  // 简洁形式：路由+方式（不用 advice 全文截断）
    const t = { id: Date.now(), label, slot: a.slot ?? 0, status: 'running', advice: a.advice }
    aiTasks.set(t.id, t)
    renderAiTasks()
    const think = addAiMsg('ai', '子 Agent 渗透执行中…')
    try {
      // 携带该流量原始请求/响应包（模型 VULNDOC 未输出时后端兜底写入漏洞库，方便用户复制复测）
      const det = a.id ? await fetch(`${API}/api/flows/${a.id}/detail`).then((x) => x.json()).catch(() => null) : null
      const reqRaw = det ? `${det.reqLine || ''}\n${(det.reqRawHeaders || []).join('\n')}\n\n${det.reqBody || ''}`.trim() : ''
      const resRaw = det ? `${det.resLine || ''}\n${(det.resRawHeaders || []).join('\n')}\n\n${det.resBody || ''}`.trim() : ''
      const r = await fetch(`${API}/api/penetrate`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ advice: a.advice, slot: a.slot, reqRaw, resRaw }) }).then((x) => x.json())
      think.remove()
      if (!r.started) {
        // 后端查重拒绝（该目标API渗透方式已进行过）：删任务条 + 意见卡状态改为"已有其他Agent渗透历史 自动跳过"
        aiTasks.delete(t.id)
        renderAiTasks()
        for (const w of document.querySelectorAll('#aiChatMsgs [data-role="ai"]')) {
          if (t.advice && w.textContent.includes(t.advice.slice(0, 20))) {
            const st = [...w.querySelectorAll('div')].find((d) => d.textContent.includes('已确认进行渗透') || d.textContent.includes('渗透执行中'))
            if (st) st.textContent = '已有其他Agent渗透历史 自动跳过'
            // 已跳过卡（无后台任务）→ 30s 自动淡出移除
            setTimeout(() => { w.style.transition = 'opacity .5s'; w.style.opacity = '0'; setTimeout(() => w.remove(), 600) }, 30000)
            break
          }
        }
        return
      }
      // 异步执行：后端立即返回 {started:true}；完成经 SSE penetrate-done 更新任务 reply/状态（不进主聊天框）
      t.status = 'running'
      renderAiTasks()
    } catch (e) {
      think.remove()
      addAiMsg('ai', `（渗透执行失败：${e.message}）`)
      t.status = 'cancelled'
      renderAiTasks()
    }
  }
  cancel.onclick = () => { closeCard('✕ 已取消渗透'); resumeSlot() }
  reply.onclick = () => { closeCard('↩ 已选中该子 Agent，输入内容将直接与它沟通'); aiReplyRef = a.advice; aiReplyRefSlot = a.slot ?? 0; aiInput.value = ''; aiInput.placeholder = '回复该子 Agent…'; aiInput.focus() }
}
let aiReplyRef = ''        // 回复引用（点回复 ICON 后设置；不点则空 = 正常与主 Agent 对话）
let aiReplyRefSlot = 0     // 被回复意见对应的子 Agent 槽位（回复走该槽位会话）
// ---- 后台任务列表（Hermes 官方 GUI 风格：输入框上方折叠列表，展开查看子 Agent/取消/点击沟通） ----
const aiTasks = new Map()  // id → {id, label, slot, status: running|done|cancelled}
function renderAiTasks() {
  const bar = document.getElementById('aiTasksBar')
  const n = aiTasks.size
  if (!n) { bar.style.display = 'none'; return }
  bar.style.display = 'block'
  document.getElementById('aiTasksTitle').textContent = `${n} 个后台任务`
  const list = document.getElementById('aiTasksList')
  list.innerHTML = ''
  for (const t of aiTasks.values()) {
    const row = document.createElement('div')
    row.style.cssText = 'display:flex;align-items:center;gap:6px;padding:5px 10px;cursor:pointer;font-size:11px;color:#d7dde4;border-top:1px solid #262c36'
    row.title = '点击与子 Agent 沟通'
    const st = t.status === 'running' ? '<span class="an-spinner" style="width:12px;height:12px;flex-shrink:0"></span>' : t.status === 'done' ? '<span style="color:#5cd67a">✓</span>' : '<span style="color:#f76b6b">✕</span>'
    row.innerHTML = `${st}<span style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${t.label}</span>`
    const cancel = document.createElement('button')
    cancel.title = '取消任务'
    cancel.style.cssText = 'background:none;border:none;color:#f76b6b;cursor:pointer;padding:2px;flex-shrink:0;opacity:.8'
    cancel.innerHTML = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="#f76b6b" stroke-width="2.4" stroke-linecap="round"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>'
    cancel.onclick = async (e) => {
      e.stopPropagation()
      // 先更新 UI（不依赖 fetch 结果——fetch 卡住也立即生效）
      const m = (t.advice || '').match(/分析\s*(\S+?)\s*可进行\s*(.+?)\s*渗透/)
      const cancelTxt = t.reply ? '已有成果 被用户中断' : `已由用户取消 ${m ? m[1] + ' ' + m[2] : t.label} 渗透`
      for (const w of document.querySelectorAll('#aiChatMsgs [data-role="ai"]')) {
        if (t.advice && w.textContent.includes(t.advice.slice(0, 20))) {
          const st = [...w.querySelectorAll('div')].find((d) => d.textContent.includes('已确认进行渗透') || d.textContent.includes('渗透执行中'))
          if (st) st.textContent = cancelTxt
          // 已处理卡（不在后台任务列表）→ 30s 自动淡出移除
          setTimeout(() => { w.style.transition = 'opacity .5s'; w.style.opacity = '0'; setTimeout(() => w.remove(), 600) }, 30000)
          break
        }
      }
      aiTasks.delete(t.id)  // 取消后自动删除对应任务条（子 Agent 释放槽位继续流量分析）
      renderAiTasks()
      // 后端取消（fire-and-forget：失败/卡住不影响 UI）
      fetch(`${API}/api/penetrate/cancel`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ slot: t.slot }) }).catch(() => {})
    }
    row.appendChild(cancel)
    row.onclick = () => openAgentChat(t)
    list.appendChild(row)
  }
}
// 折叠/展开
document.getElementById('aiTasksHead').onclick = () => {
  const list = document.getElementById('aiTasksList')
  list.style.display = list.style.display === 'none' ? 'block' : 'none'
  document.getElementById('aiTasksChevron').style.transform = list.style.display === 'none' ? '' : 'rotate(180deg)'
}
// 与子 Agent 沟通弹窗（点击任务记录打开；窗口内对话走 /api/penetrate 对应槽位）
let agentChatOpen = null  // 当前打开的任务 id
function openAgentChat(t) {
  agentChatOpen = t.id
  const ov = document.createElement('div')
  ov.id = 'agentChatOv'
  ov.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.55);z-index:999;display:flex;align-items:center;justify-content:center'
  const win = document.createElement('div')
  win.style.cssText = 'width:420px;max-width:90vw;height:480px;max-height:80vh;background:#131a22;border:1px solid #2c3542;border-radius:8px;display:flex;flex-direction:column;overflow:hidden'
  win.innerHTML = `<div style="display:flex;align-items:center;padding:8px 12px;border-bottom:1px solid #262c36;background:#151b24"><span style="flex:1;font-size:12px;color:#d7dde4;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">子 Agent · ${t.label}</span><button id="agentChatClose" style="background:none;border:none;color:#8b98a8;cursor:pointer;font-size:14px">✕</button></div><div id="agentChatMsgs" style="flex:1;overflow-y:auto;padding:10px;display:flex;flex-direction:column;gap:6px;font-size:12px"></div><div style="display:flex;gap:6px;padding:8px;border-top:1px solid #262c36"><input id="agentChatInput" placeholder="与该子 Agent 沟通…" style="flex:1;background:#111418;border:1px solid #2c3542;color:#d7dde4;padding:6px 8px;border-radius:4px;font-size:12px;outline:none"><button id="agentChatSend" style="background:#1e3a5f;border:1px solid #2c3542;color:#d7dde4;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:12px">发送</button></div>`
  ov.appendChild(win)
  document.body.appendChild(ov)
  const msgs = win.querySelector('#agentChatMsgs')
  const input = win.querySelector('#agentChatInput')
  // 打开窗口即显示该子 Agent 的历史渗透回复（完整 VULNDOC）
  if (t.reply) {
    const a = document.createElement('div')
    a.style.cssText = 'align-self:flex-start;background:#16212e;border:1px solid #2c3542;color:#d7dde4;padding:6px 9px;border-radius:6px;max-width:92%;white-space:pre-wrap;font-size:11px'
    a.textContent = t.reply
    msgs.appendChild(a)
    msgs.scrollTop = msgs.scrollHeight
  }
  const send = async () => {
    const msg = input.value.trim()
    if (!msg || win.dataset.busy === '1') return
    input.value = ''
    const u = document.createElement('div')
    u.style.cssText = 'align-self:flex-end;background:#1e3a5f;color:#d7dde4;padding:5px 9px;border-radius:6px;max-width:85%'
    u.textContent = msg
    msgs.appendChild(u)
    msgs.scrollTop = msgs.scrollHeight
    const think = document.createElement('div')
    think.style.cssText = 'align-self:flex-start;color:#8b98a8;padding:4px;display:flex;align-items:center;gap:6px'
    think.innerHTML = '<span class="an-spinner"></span>子 Agent 思考中…'  // 转圈 ICON 与流量表 analyzing 一致
    msgs.appendChild(think)
    // 发送/运行期间按钮变 Stop/Steer（动态：输入框有文字 → Steer 注入引导；空 → Stop）
    const btn = win.querySelector('#agentChatSend')
    win.dataset.busy = '1'
    const subStop = () => {
      try { fetch(`${API}/api/penetrate/cancel`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ slot: t.slot }) }) } catch { /* 已结束 */ }
      pendingSubRuns.delete(t.slot)
      think.remove()
      const a = document.createElement('div')
      a.style.cssText = 'align-self:flex-start;color:#f76b6b;padding:4px;font-size:11px'
      a.textContent = '✕ 已停止'
      msgs.appendChild(a)
      msgs.scrollTop = msgs.scrollHeight
      restore()
    }
    const subSteer = async () => {
      const text = input.value.trim()
      if (!text) return
      input.value = ''
      refreshSubBtn()
      try {
        const r = await fetch(`${API}/api/penetrate/steer`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ text, slot: t.slot }) }).then((x) => x.json())
        const a = document.createElement('div')
        a.style.cssText = 'align-self:flex-start;color:#f0b35c;padding:4px;font-size:11px'
        a.textContent = r.accepted
          ? `↪ 已向运行中的子 Agent 注入引导：${text}`
          : `（子 Agent 当前无活跃运行，引导未接受${r.reason ? `：${r.reason}` : ''}）`
        msgs.appendChild(a)
        msgs.scrollTop = msgs.scrollHeight
      } catch (e) {
        const a = document.createElement('div')
        a.style.cssText = 'align-self:flex-start;color:#f76b6b;padding:4px;font-size:11px'
        a.textContent = `（引导失败：${e.message}）`
        msgs.appendChild(a)
      }
      refreshSubBtn()
    }
    const restore = () => {
      win.dataset.busy = '0'
      input.removeEventListener('input', refreshSubBtn)
      btn.textContent = '发送'
      btn.style.background = '#1e3a5f'
      btn.style.color = '#d7dde4'
      btn.onclick = send
    }
    const refreshSubBtn = () => {
      if (win.dataset.busy !== '1') return
      const hasText = input.value.trim().length > 0
      if (hasText) {
        btn.textContent = 'Steer'
        btn.style.background = '#3a2a1e'
        btn.style.color = '#f0b35c'
        btn.onclick = subSteer
      } else {
        btn.textContent = 'Stop'
        btn.style.background = '#3a2020'
        btn.style.color = '#f76b6b'
        btn.onclick = subStop
      }
    }
    input.addEventListener('input', refreshSubBtn)
    refreshSubBtn()
    // 结果经 penetrate-done SSE 送达（/api/penetrate 异步返回 started:true）
    pendingSubRuns.set(t.slot, {
      show: (reply) => {
        think.remove()
        const a = document.createElement('div')
        a.style.cssText = 'align-self:flex-start;background:#16212e;border:1px solid #2c3542;color:#d7dde4;padding:5px 9px;border-radius:6px;max-width:85%;white-space:pre-wrap'
        a.textContent = reply || '（子 Agent 无响应）'
        msgs.appendChild(a)
        msgs.scrollTop = msgs.scrollHeight
        restore()
      },
    })
    try {
      const r = await fetch(`${API}/api/penetrate`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ advice: msg, slot: t.slot }) }).then((x) => x.json())
      // 后端查重直接拒绝（started:false + reply 立即返回）→ 不再等 SSE
      if (!r.started) {
        pendingSubRuns.delete(t.slot)
        think.remove()
        const a = document.createElement('div')
        a.style.cssText = 'align-self:flex-start;background:#16212e;border:1px solid #2c3542;color:#d7dde4;padding:5px 9px;border-radius:6px;max-width:85%;white-space:pre-wrap'
        a.textContent = r.reply || '（子 Agent 无响应）'
        msgs.appendChild(a)
        msgs.scrollTop = msgs.scrollHeight
        restore()
      }
    } catch (e) {
      pendingSubRuns.delete(t.slot)
      think.remove()
      const a = document.createElement('div')
      a.textContent = `（沟通失败：${e.message}）`
      a.style.cssText = 'align-self:flex-start;color:#f76b6b;padding:4px'
      msgs.appendChild(a)
      restore()
    }
  }
  win.querySelector('#agentChatSend').onclick = send
  input.onkeydown = (e) => { if (e.key === 'Enter') send() }
  win.querySelector('#agentChatClose').onclick = () => { ov.remove(); agentChatOpen = null; pendingSubRuns.delete(t.slot) }
  input.focus()
}
// ---- 上游设置（在设置页，见 btnSaveUp） ----

// ---- 浏览器 ----
const evalOut = document.getElementById('evalOut')
// ---- 设置（localStorage 持久化） ----
const SKEY = 'pentbox.settings'
function loadSettings() {
  try { return JSON.parse(localStorage.getItem(SKEY) || '{}') } catch { return {} }
}
function saveSettings(patch) {
  const s = { ...loadSettings(), ...patch }
  localStorage.setItem(SKEY, JSON.stringify(s))
  return s
}
// 列宽恢复（必须在此处：SKEY/loadSettings 已定义，TDZ 之前调用会中断 app.js）
initFlowResizers('#intTable', 'intCols')
initFlowResizers()
// 回填表单
{
  const s = loadSettings()
  if (s.upstream) {
    document.getElementById('setUpType').value = s.upstream.type
    document.getElementById('setUpHost').value = s.upstream.host || ''
    document.getElementById('setUpPort').value = s.upstream.port || ''
    document.getElementById('setUpUser').value = s.upstream.username || ''
    document.getElementById('setUpPass').value = s.upstream.password || ''
  }
  if (s.forward) {
    document.getElementById('setFwdMode').value = s.forward.mode
    document.getElementById('setFwdCustom').value = s.forward.custom || ''
  }
}
// MITM（HTTPS 抓包）：开关 + CA 证书下载
document.getElementById('mitmOn').onchange = async (e) => {
  await fetch(`${API}/api/mitm/state`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ enabled: e.target.checked }) })
  document.getElementById('mitmState').textContent = e.target.checked ? '已开启（浏览器需信任 CA 或已带 --ignore-certificate-errors）' : '已关闭'
}
document.getElementById('btnMitmCa').onclick = async () => {
  try {
    const j = await fetch(`${API}/api/mitm/ca`).then((r) => r.json())
    const blob = new Blob([j.pem], { type: 'application/x-x509-ca-cert' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = 'pentbox-ca.crt'
    a.click()
    document.getElementById('mitmState').textContent = `CA 已下载: ${j.path}${j.trusted ? '（系统已信任 ✓）' : '（未信任，可点「一键安装 CA」）'}`
  } catch (e) { document.getElementById('mitmState').textContent = '获取失败: ' + e.message }
}
document.getElementById('btnMitmInstall').onclick = async () => {
  const st = document.getElementById('mitmState')
  st.textContent = '安装中…'
  try {
    const j = await fetch(`${API}/api/mitm/ca/install`, { method: 'POST' }).then((r) => r.json())
    st.textContent = j.ok ? 'CA 已安装到系统信任库 ✓（浏览器下次启动走真证书校验）' : '安装失败: ' + (j.error || '')
  } catch (e) { st.textContent = '安装异常: ' + e.message }
}
// 本地 Hermes 验证（工作台 API 可达性；Hermes 对话即本地指挥通道）
document.getElementById('btnTestLocal').onclick = async () => {
  const st = document.getElementById('hermesState')
  st.textContent = '检查中…'
  try {
    const r = await fetch(`${API}/api/status`)
    const j = await r.json()
    st.textContent = `工作台 API 正常（127.0.0.1:${j.proxy?.port ?? 8877}）——本地 Hermes 对话可直接指挥浏览器/流量/SSH`
  } catch {
    st.textContent = '工作台 API 不可达'
  }
}
// 查看本地 Hermes LLM 配置（只读 config.yaml）
document.getElementById('btnLocalHermes').onclick = async () => {
  const st = document.getElementById('llmState')
  st.textContent = '读取中…'
  try {
    const r = await fetch(`${API}/api/hermes/local-config`)
    const j = await r.json()
    if (j.model) st.textContent = `本地 Hermes 模型: ${j.model.default}（provider: ${j.model.provider}${j.model.base_url ? ' @ ' + j.model.base_url : ''}，api_key: ${j.model.api_key || '无'}）`
    else st.textContent = '失败: ' + (j.error || '')
  } catch (e) { st.textContent = '读取异常: ' + e.message }
}
// 上游
document.getElementById('btnSaveUp').onclick = async () => {
  const type = document.getElementById('setUpType').value
  const body = type === 'direct' ? { type } : {
    type,
    host: document.getElementById('setUpHost').value,
    port: Number(document.getElementById('setUpPort').value) || undefined,
    username: document.getElementById('setUpUser').value || undefined,
    password: document.getElementById('setUpPass').value || undefined,
  }
  const r = await fetch(`${API}/api/upstream`, { method: 'PUT', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
  const j = await r.json()
  if (j.ok) { saveSettings({ upstream: body }); document.getElementById('upState').textContent = '已保存并应用' }
  else document.getElementById('upState').textContent = '失败: ' + (j.error || '')
}
// 转发
document.getElementById('btnSaveFwd').onclick = () => {
  const fwd = {
    mode: document.getElementById('setFwdMode').value,
    custom: document.getElementById('setFwdCustom').value,
  }
  saveSettings({ forward: fwd })
  document.getElementById('fwdState').textContent = '已保存（下次启动浏览器生效）'
}
// 浏览器 launch 时应用转发设置（浏览器默认走内置代理抓包；customProxy 用于转发 Burp）
document.getElementById('btnLaunch').onclick = async () => {
  const engine = document.getElementById('engineSel').value
  evalOut.textContent = `正在启动 ${engine}…`
  try {
    const s = loadSettings()
    const fwd = s.forward || { mode: 'system' }
    const body = { engine, headless: false }
    if (fwd.mode === 'custom' && fwd.custom) {
      const [h, p] = fwd.custom.split(':')
      body.customProxy = `${h}:${p}`  // ponytail: 自定义转发目标（Burp）由主进程 launch 参数使用
    }
    const r = await fetch(`${API}/api/browser/launch`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })
    evalOut.textContent = JSON.stringify(await r.json(), null, 2)
  } catch (e) { evalOut.textContent = '启动失败: ' + e.message }
}
document.getElementById('btnStop').onclick = async () => {
  await fetch(`${API}/api/browser/stop`, { method: 'POST' })
  evalOut.textContent = '已停止'
}
document.getElementById('btnNav').onclick = async () => {
  const url = document.getElementById('navUrl').value || 'about:blank'
  const r = await fetch(`${API}/api/browser/navigate`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url }) })
  evalOut.textContent = JSON.stringify(await r.json(), null, 2)
}
document.getElementById('btnEval').onclick = async () => {
  const expression = document.getElementById('evalBox').value
  if (!expression) return
  const r = await fetch(`${API}/api/browser/eval`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ expression }) })
  const j = await r.json()
  evalOut.textContent = '> ' + expression + '\n' + JSON.stringify(j.result ?? j.error ?? j, null, 2)
}

// ---- 远程 LLM 配置管理（已移除：SSH 方式被否决；改为 gateway 原生运行时模型覆盖，见 Hermes 对接卡片） ----

// ================= LLM 管理（参考 hermes-studio models store：多 LLM 配置 CRUD + 默认） =================
// settings.llms: [{name, baseUrl, apiKey, model, reasoning, isDefault}]
function llms() { return loadSettings().llms || [] }
function saveLlms(list) { saveSettings({ llms: list }) }
function renderLlms() {
  const sel = document.getElementById('llmList')
  const list = llms()
  sel.innerHTML = ''
  if (!list.length) {
    const opt = document.createElement('option')
    opt.value = ''
    opt.textContent = '（无 LLM 配置）'
    sel.appendChild(opt)
    return
  }
  for (const [i, l] of list.entries()) {
    const opt = document.createElement('option')
    opt.value = String(i)
    opt.textContent = `${l.isDefault ? '★ ' : ''}${l.name} — ${l.model}${l.reasoning ? ' [' + l.reasoning + ']' : ''}`
    sel.appendChild(opt)
  }
}
function llmFormValue() {
  return {
    name: document.getElementById('llmName').value.trim(),
    baseUrl: document.getElementById('llmBase').value.trim(),
    apiKey: document.getElementById('llmKey').value.trim(),
    model: document.getElementById('llmModel').value.trim(),
    provider: document.getElementById('llmProvider').value.trim(),
    reasoning: document.getElementById('llmReasoning').value,
  }
}
// Provider 推断：显式值优先，否则按端点域名（deepseek/minimax 等）
function llmProviderOf(l) {
  if (l.provider) return l.provider === 'minimax' ? 'minimax-cn' : l.provider  // Hermes 官方名 minimax-cn
  const b = (l.baseUrl || '').toLowerCase()
  if (b.includes('minimax')) return 'minimax-cn'
  if (b.includes('deepseek')) return 'deepseek'
  if (b.includes('openai')) return 'openai'
  if (b.includes('anthropic')) return 'anthropic'
  if (b.includes('moonshot')) return 'moonshot'
  if (b.includes('siliconflow')) return 'siliconflow'
  return ''
}
function llmFillForm(l) {
  document.getElementById('llmName').value = l.name || ''
  document.getElementById('llmBase').value = l.baseUrl || ''
  document.getElementById('llmKey').value = l.apiKey || ''
  document.getElementById('llmModel').value = l.model || ''
  document.getElementById('llmProvider').value = l.provider || ''
  document.getElementById('llmReasoning').value = l.reasoning || ''
}
function defaultLlm() { return llms().find((l) => l.isDefault) || llms()[0] }
document.getElementById('btnLlmSave').onclick = () => {
  const v = llmFormValue()
  if (!v.name || !v.baseUrl || !v.model) { document.getElementById('llmState').textContent = '名称/端点/模型必填'; return }
  const list = llms()
  const idx = Number(document.getElementById('llmList').value)
  if (Number.isInteger(idx) && list[idx]) list[idx] = { ...list[idx], ...v }
  else list.push(v)
  saveLlms(list)
  renderLlms()
  document.getElementById('llmState').textContent = '已保存'
  document.getElementById('llmKey').value = '' // 防留明文
}
document.getElementById('llmList').onchange = () => {
  const idx = Number(document.getElementById('llmList').value)
  const l = llms()[idx]
  if (l) llmFillForm(l)
}
document.getElementById('btnLlmDelete').onclick = () => {
  const idx = Number(document.getElementById('llmList').value)
  if (!Number.isInteger(idx)) return
  const list = llms()
  list.splice(idx, 1)
  saveLlms(list)
  renderLlms()
  document.getElementById('llmState').textContent = '已删除'
}
document.getElementById('btnLlmApply').onclick = async () => {
  const idx = Number(document.getElementById('llmList').value)
  if (!Number.isInteger(idx)) return
  const list = llms()
  for (const l of list) l.isDefault = false
  list[idx].isDefault = true
  saveLlms(list)
  renderLlms()
  document.getElementById('llmState').textContent = `已设为默认：${list[idx].name}`
  // 同步写入 hermespentbox 档案 config.yaml（模型/端点/Key 全量；应用 Agent 实际使用该配置）
  try {
    const llm = list[idx]
    await fetch(`${API}/api/llms/set-default`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ model: llm.model, provider: llmProviderOf(llm), baseUrl: llm.baseUrl, apiKey: llm.apiKey }) })
  } catch { /* 写入失败不影响本地 */ }

}
// 加载时：从 hermespentbox 档案 config 拉当前模型，无本地默认则用档案配置
;(async () => {
  try {
    const r = await fetch(`${API}/api/hermes/local-config`)
    const j = await r.json()
    const cur = j.model?.default
    if (cur && !llms().some((l) => l.isDefault)) {
      const list = llms()
      const hit = list.find((l) => l.model === cur) || list[0]
      if (hit) {
        for (const l of list) l.isDefault = false
        hit.isDefault = true
        saveLlms(list)
        renderLlms()
        document.getElementById('llmState').textContent = `默认模型（档案）：${cur}`
      }
    }
  } catch { /* 拉取失败忽略 */ }
})()
document.getElementById('btnLlmTest').onclick = async () => {
  const idx = Number(document.getElementById('llmList').value)
  const l = llms()[idx]
  if (!l) { document.getElementById('llmState').textContent = '请先选择 LLM'; return }
  const st = document.getElementById('llmState')
  st.textContent = '测试中…'
  const r = await fetch(`${API}/api/llm/test`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ baseUrl: l.baseUrl, apiKey: l.apiKey, model: l.model }) })
  const j = await r.json()
  st.textContent = j.ok ? `直连 OK（${j.model}）` : '直连失败: ' + (j.error || '')
}
renderLlms()
// 首个 LLM 自动设为默认（迁移历史配置：hermes.model/baseUrl/apiKey/reasoning → llms[0]）
if (!llms().length) {
  const h = loadSettings().hermes || {}
  if (h.baseUrl || h.model) {
    saveLlms([{ name: h.model || 'LLM-1', baseUrl: h.baseUrl || '', apiKey: h.apiKey || '', model: h.model || '', reasoning: h.reasoning || '', isDefault: true }])
    renderLlms()
  }
}

// ---- AI 助手（对接 kali Hermes gateway，事件流渲染参考 hermes desktop 消息流） ----
// ---- SSH 终端 ----
const term = new Terminal({ cursorBlink: true, fontSize: 13, theme: { background: '#111418', foreground: '#d7dde4' } })
term.open(document.getElementById('term'))
let ws = null
let shellReady = false
document.getElementById('btnSsh').onclick = () => {
  const opts = {
    host: document.getElementById('sshHost').value,
    port: Number(document.getElementById('sshPort').value) || 22,
    username: document.getElementById('sshUser').value,
    password: document.getElementById('sshPass').value,
  }
  if (!opts.host || !opts.username) { alert('填 host/user'); return }
  ws = new WebSocket(WS)
  ws.onopen = () => ws.send(JSON.stringify({ type: 'connect', opts }))
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data)
    if (m.type === 'ready') { shellReady = true; document.getElementById('sshState').textContent = '已连接'; term.focus() }
    else if (m.type === 'data') term.write(m.data)
    else if (m.type === 'closed') { shellReady = false; document.getElementById('sshState').textContent = '会话关闭' }
    else if (m.type === 'error') term.write('\r\n[ERR] ' + m.error + '\r\n')
  }
}
term.onData((data) => { if (ws && ws.readyState === 1 && shellReady) ws.send(JSON.stringify({ type: 'input', data })) })
