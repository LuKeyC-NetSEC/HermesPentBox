/**
 * VULNDOC 解析器（纯函数）：从子 Agent 渗透回复中提取结构化漏洞文档
 * 兼容省略【VULNDOC】标记（检测"原始请求包："即视为文档正文）；可独立单测
 */

export type VulnLevel = 'high' | 'medium' | 'low' | 'info'

export interface ParsedVulndoc {
  name: string
  level: VulnLevel
  /** 完整定位 URI：漏洞目标 + 漏洞路由（如 http://127.0.0.1:8800/api/login） */
  uri: string
  desc: string
  exploit: string
  reqRaw: string
  resRaw: string
}

/** 清洗原始报文：去掉 ``` markdown 围栏行 */
function cleanRaw(s: string): string {
  return s.split('\n').filter((l) => !l.trim().startsWith('```')).join('\n').trim()
}

/**
 * 解析渗透回复中的漏洞文档；无文档返回 null
 * @param reply 子 Agent 渗透回复全文
 * @param fallbackReqRaw 模型未输出请求包时的兜底（前端携带的原始请求）
 * @param fallbackResRaw 模型未输出响应包时的兜底
 */
export function parseVulndoc(reply: string, fallbackReqRaw = '', fallbackResRaw = ''): ParsedVulndoc | null {
  const docBody = reply.includes('【VULNDOC】')
    ? (reply.match(/【VULNDOC】\s*\n([\s\S]*?)(?=\n【|$)/) || [])[1] ?? ''
    : /原始请求包[:：]/.test(reply) ? reply : ''
  if (!docBody) return null
  const g = (k: string) => (docBody.match(new RegExp(`${k}[:：]\\s*(.+)`)) || [])[1]?.trim() ?? ''
  // 危害等级：关键词匹配（high/medium/中/low/低）
  const levelRaw = g('危害等级').toLowerCase()
  const level: VulnLevel = levelRaw.includes('high') ? 'high'
    : levelRaw.includes('medium') || levelRaw.includes('中') ? 'medium'
      : levelRaw.includes('low') || levelRaw.includes('低') ? 'low' : 'info'
  const uri = `${g('漏洞目标') || ''}${g('漏洞路由') || ''}`  // 目标+路由（完整定位）
  // 标题清洗：去掉开头路由前缀（如 "/api/login 未授权访问" → "未授权访问"——先 trim 再去前缀，防前导空格绕过）
  const rawName = (g('标题') || '子 Agent 渗透发现').trim().replace(/^https?:\/\/[^\s]+\s+/, '').replace(/^\/[^\s]+\s+/, '').trim()
  // 复现步骤 → exploit；desc 只含漏洞描述 + 修复建议（不重复）
  return {
    name: rawName || '子 Agent 渗透发现',
    level,
    uri,
    desc: `${g('漏洞描述')}\n\n修复建议：${g('修复建议')}`.slice(0, 2000),
    exploit: g('复现步骤'),
    reqRaw: cleanRaw((docBody.match(/原始请求包[:：]\s*([\s\S]*?)(?=\n原始响应包[:：]|$)/) || [])[1]?.trim() || fallbackReqRaw || '').slice(0, 4000),
    resRaw: cleanRaw((docBody.match(/原始响应包[:：]\s*([\s\S]*?)$/) || [])[1]?.trim() || fallbackResRaw || '').slice(0, 4000),
  }
}
