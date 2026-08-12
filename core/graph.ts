/**
 * Neo4j Agent 情报图：完全替代原"全局情报 digest"文本摘要。
 * 结构化存储会话/目标/接口/漏洞/凭据/渗透状态，供主 Agent 与子 Agent 跨会话共享上下文。
 *
 * Schema:
 *   (:Host {url})
 *   (:Api {host, path, method})
 *   (:Vuln {name, level, desc, host, path, exploit})
 *   (:Cred {type, value, host, path, source})
 *   (:WebShell {id, type, script, url, password, key, cryption, payload, encoding, remark, ts})
 *   (:Note {kind, text, host, path, agent, persist, ts})
 *   (:Penetration {host, path, method, status, slot, ts})
 * 关系:
 *   (Host)-[:HAS_API]->(Api)
 *   (Api)-[:HAS_VULN]->(Vuln)
 *   (Host)-[:HAS_CRED]->(Cred)
 *   (Host)-[:HAS_SHELL]->(WebShell)
 *   (Host)-[:HAS_NOTE]->(Note)
 */
import neo4j from 'neo4j-driver'

export interface VulnData { name?: string; level?: string; desc?: string; host: string; path: string; exploit?: string; color?: string }
export interface CredData { type: string; value: string; host: string; path: string; source?: string; tag?: string; group?: string; level?: string; color?: string }
export interface WebShellData { id: number; type?: string; script?: string; url: string; password?: string; key?: string; cryption?: string; payload?: string; encoding?: string; remark?: string; status?: string; ts: number }
export interface NoteData { kind: string; text: string; host: string; path: string; agent?: string; persist?: boolean; tag?: string; group?: string; level?: string; color?: string }
export interface PenData { host: string; path: string; method: string; status: 'penetrating' | 'penetrated' | 'cancelled'; slot?: number; detail?: string }
export interface AnalysisData { host: string; path: string; method: string; level?: string; vuln?: boolean; advice?: string; sens?: string; sensCount?: number; color?: string; confirmed?: boolean }

export class Neo4jGraph {
  private driver: ReturnType<typeof neo4j.driver> | null = null
  private enabledFlag = false

  constructor(
    private url = 'bolt://localhost:7687',
    private user = 'neo4j',
    private pass = 'pentbox123',
  ) {}

  get enabled(): boolean { return this.enabledFlag && !!this.driver }

  connect(): void {
    try {
      this.driver = neo4j.driver(this.url, neo4j.auth.basic(this.user, this.pass), { encrypted: false })
      this.enabledFlag = true
    } catch { this.enabledFlag = false }
  }

  async close(): Promise<void> {
    if (this.driver) { try { await this.driver.close() } catch { /* */ } }
    this.driver = null
    this.enabledFlag = false
  }

  private async run(query: string, params?: Record<string, unknown>): Promise<void> {
    if (!this.enabled) return
    const s = this.driver!.session()
    try { await s.run(query, params || {}) } catch { /* 单条失败不阻塞 */ } finally { await s.close() }
  }

  private async read(query: string, params?: Record<string, unknown>): Promise<any[]> {
    if (!this.enabled) return []
    const s = this.driver!.session()
    try { const r = await s.run(query, params || {}); return r.records } catch { return [] } finally { await s.close() }
  }

  // ---------------- 写入 ----------------

  /** 目标/接口（Api 唯一键 = host+path：站点地图/漏洞/凭据/分析全挂同一节点，method 仅作属性更新） */
  async upsertHostApi(host: string, path: string, method = 'GET'): Promise<void> {
    await this.run(
      `MERGE (h:Host {url:$host})
       MERGE (h)-[:HAS_API]->(a:Api {host:$host, path:$path})
       SET a.method=$method, a.lastSeen=timestamp()`,
      { host, path, method },
    )
  }

  /** 流量分析结论（挂 Api 节点：与站点地图同一条路径链；同 host+path 覆盖最近一次分析）
   * Api.color = 该条目最高敏感等级色（HAE）；Analysis.vuln=true 未渗透确认 = 疑似漏洞（前端问号 ICON 语义） */
  async writeAnalysis(a: AnalysisData): Promise<void> {
    await this.run(
      `MERGE (h:Host {url:$host})
       MERGE (h)-[:HAS_API]->(a:Api {host:$host, path:$path})
       SET a.method=$method, a.lastSeen=timestamp(), a.color=$color
       MERGE (a)-[:ANALYZED]->(an:Analysis {host:$host, path:$path})
       SET an.level=$level, an.vuln=$vuln, an.confirmed=$confirmed, an.advice=$advice, an.sens=$sens, an.sensCount=$sensCount, an.ts=timestamp()`,
      { host: a.host, path: a.path, method: a.method || 'GET', level: a.level || 'info', vuln: a.vuln === true, confirmed: a.confirmed === true, advice: a.advice || '', sens: a.sens || '', sensCount: a.sensCount || 0, color: a.color || '' },
    )
  }

  /** 渗透确认 → Analysis 节点标记 confirmed（疑似漏洞 → 已确认；配合 Vuln 节点双标识，Agent 图查询可见确认状态） */
  async confirmAnalysis(host: string, path: string, level: string): Promise<void> {
    await this.run(
      `MATCH (a:Api {host:$host, path:$path})-[:ANALYZED]->(an:Analysis {host:$host, path:$path})
       SET an.confirmed=true, an.level=$level`,
      { host, path, level },
    )
  }

  /** 漏洞 */
  async writeVuln(v: VulnData): Promise<void> {
    await this.run(
      `MERGE (h:Host {url:$host})
       MERGE (h)-[:HAS_API]->(a:Api {host:$host, path:$path})
       MERGE (a)-[:HAS_VULN]->(vn:Vuln {host:$host, path:$path, name:$name})
       SET vn.level=$level, vn.desc=$desc, vn.exploit=$exploit, vn.color=$color, vn.ts=timestamp()`,
      { host: v.host, path: v.path, name: v.name || '未命名漏洞', level: v.level || 'info', desc: v.desc || '', exploit: v.exploit || '', color: v.color || '' },
    )
  }

  /** 凭据（HaENet 标签元数据随节点写入：tag/group/level/color） */
  async writeCred(c: CredData): Promise<void> {
    await this.run(
      `MERGE (h:Host {url:$host})
       MERGE (h)-[:HAS_CRED]->(cr:Cred {type:$type, value:$value, host:$host, path:$path})
       SET cr.source=$source, cr.tag=$tag, cr.group=$group, cr.level=$level, cr.color=$color, cr.ts=timestamp()`,
      { host: c.host, path: c.path, type: c.type, value: c.value, source: c.source || '', tag: c.tag || '', group: c.group || '', level: c.level || '', color: c.color || '' },
    )
  }

  /** WebShell（挂 Host 节点，按 url 唯一；密码/密钥完整入库供 Agent 复用） */
  async writeWebShell(ws: WebShellData): Promise<void> {
    // host 统一无协议格式（host:port，与其他写入一致，避免 Host 节点分裂）
    let host = ''
    try { host = new URL(ws.url).host } catch { host = ws.url.match(/^[a-zA-Z0-9.\-]+(?::\d+)?/)?.[0] || ws.url }
    await this.run(
      `MERGE (h:Host {url:$host})
       MERGE (h)-[:HAS_SHELL]->(sh:WebShell {url:$url})
       SET sh.id=$id, sh.type=$type, sh.script=$script, sh.password=$password, sh.key=$key,
           sh.cryption=$cryption, sh.payload=$payload, sh.encoding=$encoding, sh.remark=$remark,
           sh.status=$status, sh.ts=$ts`,
      { host, url: ws.url, id: ws.id, type: ws.type || 'custom', script: ws.script || 'php', password: ws.password || '', key: ws.key || '', cryption: ws.cryption || '', payload: ws.payload || '', encoding: ws.encoding || 'UTF-8', remark: ws.remark || '', status: ws.status || 'unknown', ts: ws.ts },
    )
  }

  /** 删除 WebShell */
  async deleteWebShell(url: string): Promise<void> {
    await this.run(
      `MATCH (sh:WebShell {url:$url}) DETACH DELETE sh`,
      { url },
    )
  }

  /** 笔记/Nday/备注（HaENet 标签元数据随节点写入：tag/group/level/color） */
  async writeNote(n: NoteData): Promise<void> {
    await this.run(
      `MERGE (h:Host {url:$host})
       MERGE (h)-[:HAS_NOTE]->(nt:Note {kind:$kind, host:$host, path:$path, text:$text})
       SET nt.agent=$agent, nt.persist=$persist, nt.tag=$tag, nt.group=$group, nt.level=$level, nt.color=$color, nt.ts=timestamp()`,
      { host: n.host, path: n.path, kind: n.kind, text: n.text, agent: n.agent || '', persist: n.persist === true, tag: n.tag || '', group: n.group || '', level: n.level || '', color: n.color || '' },
    )
  }

  /** 渗透状态（进行中/已完成/已取消），同 Host+path+method 唯一 */
  async writePenetration(p: PenData): Promise<void> {
    await this.run(
      `MERGE (h:Host {url:$host})
       MERGE (h)-[:HAS_API]->(a:Api {host:$host, path:$path})
       MERGE (a)-[:PENETRATED]->(pe:Penetration {host:$host, path:$path, method:$method})
       SET pe.status=$status, pe.slot=$slot, pe.detail=$detail, pe.ts=timestamp()`,
      { host: p.host, path: p.path, method: p.method, status: p.status, slot: p.slot || 0, detail: p.detail || '' },
    )
  }

  /** 移除渗透状态（进行中取消/清除） */
  async removePenetration(host: string, path: string, method: string): Promise<void> {
    await this.run(
      `MATCH (pe:Penetration {host:$host, path:$path, method:$method}) DETACH DELETE pe`,
      { host, path, method },
    )
  }

  /** 删除漏洞（按 host+path+name 定位） */
  async removeVuln(host: string, path: string, name: string): Promise<void> {
    await this.run(
      `MATCH (v:Vuln {host:$host, path:$path, name:$name}) DETACH DELETE v`,
      { host, path, name },
    )
  }

  // ---------------- 查重 ----------------

  /** 该目标+方式是否已渗透过 */
  async isPenetrated(host: string, path: string, method: string): Promise<boolean> {
    const rows = await this.read(
      `MATCH (pe:Penetration {host:$host, path:$path, method:$method, status:'penetrated'}) RETURN count(pe) AS c`,
      { host, path, method },
    )
    return rows[0]?.get('c')?.toNumber?.() > 0 || false
  }

  /** 该目标+方式是否正在渗透 */
  async isPenetrating(host: string, path: string, method: string): Promise<boolean> {
    const rows = await this.read(
      `MATCH (pe:Penetration {host:$host, path:$path, method:$method, status:'penetrating'}) RETURN count(pe) AS c`,
      { host, path, method },
    )
    return rows[0]?.get('c')?.toNumber?.() > 0 || false
  }

  // ---------------- 上下文 ----------------

  /** 按目标生成全局情报上下文（供分析/渗透 prompt 注入） */
  /** 结构化图查询（/api/graph/query?format=json 用）：按 Host 分组返回情报对象，供 Agent 主动查图后按需分析 */
  async queryGraph(host?: string): Promise<{
    host: string
    apis: { path: string; method?: string; analysis?: { level?: string; vuln?: boolean; advice?: string } }[]
    vulns: { name: string; level?: string; path?: string }[]
    creds: { type?: string; value: string; path?: string }[]
    shells: { id?: number; url: string; type?: string; script?: string; status?: string }[]
    notes: { kind?: string; text: string; path?: string }[]
    pens: { path?: string; method?: string; status?: string }[]
  }[]> {
    if (!this.enabled) return []
    try {
      const rows = await this.read(
        `MATCH (h:Host${host ? ' {url:$host}' : ''})
         OPTIONAL MATCH (h)-[:HAS_API]->(a:Api)
         OPTIONAL MATCH (a)-[:HAS_VULN]->(v:Vuln)
         OPTIONAL MATCH (a)-[:ANALYZED]->(an:Analysis)
         OPTIONAL MATCH (h)-[:HAS_CRED]->(cr:Cred)
         OPTIONAL MATCH (h)-[:HAS_SHELL]->(sh:WebShell)
         OPTIONAL MATCH (h)-[:HAS_NOTE]->(nt:Note)
         OPTIONAL MATCH (a)-[:PENETRATED]->(pe:Penetration)
         RETURN h.url AS host,
                collect(DISTINCT {path:a.path, method:a.method, aColor:a.color, anLevel:an.level, anVuln:an.vuln, anConfirmed:an.confirmed, anAdvice:an.advice}) AS apis,
                collect(DISTINCT {name:v.name, level:v.level, path:v.path, color:v.color}) AS vulns,
                collect(DISTINCT {type:cr.type, value:cr.value, path:cr.path}) AS creds,
                collect(DISTINCT {id:sh.id, url:sh.url, type:sh.type, script:sh.script, status:sh.status}) AS shells,
                collect(DISTINCT {kind:nt.kind, text:nt.text, path:nt.path}) AS notes,
                collect(DISTINCT {path:pe.path, method:pe.method, status:pe.status}) AS pens
         ORDER BY h.url LIMIT 50`,
        { host: host || '' },
      )
      return rows.map((r) => ({
        host: String(r.get('host') || ''),
        apis: ((r.get('apis') || []).filter((x: unknown) => x && (x as { path?: string }).path) as { path: string; method?: string; aColor?: string; anLevel?: string; anVuln?: boolean; anConfirmed?: boolean; anAdvice?: string }[]).map((a) => ({ path: a.path, method: a.method, color: a.aColor, analysis: a.anLevel ? { level: a.anLevel, vuln: !!a.anVuln, confirmed: !!a.anConfirmed, advice: (a.anAdvice || '').slice(0, 200) } : undefined })),
        vulns: (r.get('vulns') || []).filter((x: unknown) => x && (x as { name?: string }).name),
        creds: (r.get('creds') || []).filter((x: unknown) => x && (x as { value?: string }).value),
        shells: (r.get('shells') || []).filter((x: unknown) => x && (x as { url?: string }).url),
        notes: (r.get('notes') || []).filter((x: unknown) => x && (x as { text?: string }).text),
        pens: (r.get('pens') || []).filter((x: unknown) => x && (x as { status?: string }).status),
      }))
    } catch { return [] }
  }

  async contextPrompt(host?: string): Promise<string> {
    if (!this.enabled) return ''
    try {
      const rows = await this.read(
        `MATCH (h:Host${host ? ' {url:$host}' : ''})
         OPTIONAL MATCH (h)-[:HAS_API]->(a:Api)
         OPTIONAL MATCH (a)-[:HAS_VULN]->(v:Vuln)
         OPTIONAL MATCH (a)-[:ANALYZED]->(an:Analysis)
         OPTIONAL MATCH (h)-[:HAS_CRED]->(cr:Cred)
         OPTIONAL MATCH (h)-[:HAS_SHELL]->(sh:WebShell)
         OPTIONAL MATCH (h)-[:HAS_NOTE]->(nt:Note)
         OPTIONAL MATCH (a)-[:PENETRATED]->(pe:Penetration)
         RETURN h.url AS host, collect(DISTINCT {path:a.path, method:a.method, aColor:a.color, anLevel:an.level, anVuln:an.vuln, anConfirmed:an.confirmed, anAdvice:an.advice}) AS apis,
                collect(DISTINCT {name:v.name, level:v.level, path:v.path, color:v.color}) AS vulns,
                collect(DISTINCT {type:cr.type, value:cr.value, path:cr.path, tag:cr.tag, level:cr.level}) AS creds,
                collect(DISTINCT {id:sh.id, url:sh.url, type:sh.type, script:sh.script, status:sh.status, password:sh.password, key:sh.key, cryption:sh.cryption}) AS shells,
                collect(DISTINCT {kind:nt.kind, text:nt.text, path:nt.path, tag:nt.tag, level:nt.level}) AS notes,
                collect(DISTINCT {path:pe.path, method:pe.method, status:pe.status}) AS pens
         ORDER BY h.url LIMIT 50`,
        { host: host || '' },
      )
      if (!rows.length) return ''
      const out: string[] = []
      for (const r of rows) {
        const h = String(r.get('host') || '')
        const apis = (r.get('apis') || []).filter((x: unknown) => x && (x as { path?: string }).path) as { path: string; method?: string; aColor?: string; anLevel?: string; anVuln?: boolean; anConfirmed?: boolean; anAdvice?: string }[]
        const vulns = (r.get('vulns') || []).filter((x: unknown) => x && (x as { name?: string }).name) as { name: string; level?: string; path?: string; color?: string }[]
        const creds = (r.get('creds') || []).filter((x: unknown) => x && (x as { value?: string }).value) as { type?: string; value: string; path?: string }[]
        const shells = (r.get('shells') || []).filter((x: unknown) => x && (x as { url?: string }).url) as { id?: number; url: string; type?: string; script?: string; status?: string; password?: string; key?: string; cryption?: string }[]
        const notes = (r.get('notes') || []).filter((x: unknown) => x && (x as { text?: string }).text) as { kind?: string; text: string; path?: string }[]
        const pens = (r.get('pens') || []).filter((x: unknown) => x && (x as { status?: string }).status) as { path?: string; method?: string; status?: string }[]
        if (!apis.length && !vulns.length && !creds.length && !shells.length && !notes.length && !pens.length) continue
        const lines: string[] = [`【目标】${h}`]
        if (apis.length) for (const a of apis.slice(0, 40)) lines.push(`  接口(${a.method || 'GET'}) ${a.path}${a.aColor ? `[${a.aColor}]` : ''}${a.anLevel ? ` 分析[${a.anLevel}${a.anVuln ? (a.anConfirmed ? '/已确认' : '/疑似') : ''}]${(a.anAdvice || '').slice(0, 60)}` : ''}`)
        if (vulns.length) for (const v of vulns.slice(0, 20)) lines.push(`  漏洞(${v.level || 'info'}${v.color ? `/${v.color}` : ''}) ${v.path || ''} ${v.name}`)
        if (creds.length) for (const c of creds.slice(0, 20)) lines.push(`  凭据[${c.tag || c.type || '?'}](${c.level || '?'}) ${c.path || ''} = ${String(c.value).slice(0, 120)}`)
        if (shells.length) for (const s of shells.slice(0, 20)) lines.push(`  WebShell(id=${s.id || '?'}/${s.type || 'custom'}/${s.script || '?'}/${s.status || 'unknown'}) ${s.url}${s.password || s.key || s.cryption ? ` [配置:${s.cryption || 'raw'}${s.password ? `/pass=${s.password}` : ''}${s.key ? `/key=${s.key}` : ''}]` : ''}`)
        if (notes.length) for (const n of notes.slice(0, 30)) lines.push(`  [${n.tag || n.kind}](${n.level || 'info'}) ${n.path || ''}：${n.text}`)
        if (pens.length) for (const p of pens.slice(0, 20)) lines.push(`  渗透(${p.status}) ${p.path || ''} ${p.method || ''}`)
        out.push(lines.join('\n'))
      }
      if (!out.length) return ''
      return `【全局情报】多 Agent 战况共享（Neo4j 会话图）：\n${out.join('\n\n')}\n（结合这些情报判断当前流量是否与已知发现关联、是否同一目标的其他风险面）\n\n`
    } catch { return '' }
  }
}
