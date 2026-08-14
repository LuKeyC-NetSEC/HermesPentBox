/**
 * HaENet 标签体系（纯数据 + 渲染）：5 组分类 + fixed level + 颜色
 * Agent 敏感提取按此输出 type，前端按此着色；凭据类标签驱动自动意见卡
 */

export type HaeGroup = 'Fingerprint' | 'Maybe Vulnerability' | 'Basic Information' | 'Sensitive Information' | 'Other'
export interface HaeTag { group: HaeGroup; cn: string; level: 'high' | 'medium' | 'low' | 'info'; color: string }
/** 标签注册表：type 名（LLM 输出）→ 分组/中文名/固定等级/颜色 */
export const HAE_TAGS: Record<string, HaeTag> = {
  // ---- Fingerprint（指纹识别，HaENet 原版） ----
  'Shiro': { group: 'Fingerprint', cn: 'Shiro 框架指纹', level: 'medium', color: '#66bb6a' },
  'JSON Web Token': { group: 'Fingerprint', cn: 'JWT 令牌指纹', level: 'medium', color: '#4fc3f7' },
  'Swagger UI': { group: 'Fingerprint', cn: 'Swagger 接口文档', level: 'medium', color: '#f76b6b' },
  'Ueditor': { group: 'Fingerprint', cn: 'Ueditor 编辑器指纹', level: 'medium', color: '#66bb6a' },
  'Druid': { group: 'Fingerprint', cn: 'Druid 监控面板', level: 'medium', color: '#f7a35c' },
  'PDF.js Viewer': { group: 'Fingerprint', cn: 'PDF.js 查看器', level: 'low', color: '#66bb6a' },
  'Vite DevMode': { group: 'Fingerprint', cn: 'Vite 开发模式', level: 'high', color: '#f76b6b' },
  // ---- Maybe Vulnerability（潜在漏洞线索，HaENet 原版） ----
  'Java Deserialization': { group: 'Maybe Vulnerability', cn: 'Java 反序列化入口', level: 'high', color: '#f7e05c' },
  'Debug Logic Parameters': { group: 'Maybe Vulnerability', cn: '调试/后门参数', level: 'medium', color: '#80cbc4' },
  'URL As A Value': { group: 'Maybe Vulnerability', cn: 'URL 作为参数值(SSRF)', level: 'medium', color: '#80cbc4' },
  'Upload Form': { group: 'Maybe Vulnerability', cn: '文件上传表单', level: 'medium', color: '#f7e05c' },
  'DoS Parameters': { group: 'Maybe Vulnerability', cn: 'DoS 类分页参数', level: 'low', color: '#80cbc4' },
  'Passwd File': { group: 'Maybe Vulnerability', cn: '口令文件泄漏', level: 'high', color: '#f76b6b' },
  'Win.ini File': { group: 'Maybe Vulnerability', cn: 'Windows 配置文件泄漏', level: 'high', color: '#f76b6b' },
  // ---- Basic Information（基础信息，HaENet 原版） ----
  'Email': { group: 'Basic Information', cn: '邮箱地址', level: 'low', color: '#ce93d8' },
  'Chinese IDCard': { group: 'Basic Information', cn: '中国大陆身份证', level: 'high', color: '#ffb74d' },
  'Chinese Mobile Number': { group: 'Basic Information', cn: '中国大陆手机号', level: 'medium', color: '#80cbc4' },
  'Internal IP Address': { group: 'Basic Information', cn: '内网 IP 地址', level: 'medium', color: '#80cbc4' },
  'MAC Address': { group: 'Basic Information', cn: 'MAC 地址', level: 'low', color: '#66bb6a' },
  // ---- Sensitive Information（敏感信息，HaENet 原版 + 兼容原凭据标签） ----
  'Cloud Key': { group: 'Sensitive Information', cn: '云厂商 AccessKey', level: 'high', color: '#f7e05c' },
  'Cloud Access Key': { group: 'Sensitive Information', cn: '云 AccessKey/Secret', level: 'high', color: '#f7e05c' },
  'Windows File/Dir Path': { group: 'Sensitive Information', cn: 'Windows 路径泄漏', level: 'medium', color: '#66bb6a' },
  'Password Field': { group: 'Sensitive Information', cn: '密码字段', level: 'high', color: '#f7a35c' },
  'Username Field': { group: 'Sensitive Information', cn: '用户名/账号字段', level: 'low', color: '#66bb6a' },
  'WeCom Key': { group: 'Sensitive Information', cn: '企业微信凭证', level: 'high', color: '#66bb6a' },
  'JDBC Connection': { group: 'Sensitive Information', cn: 'JDBC 数据库连接(明文口令)', level: 'high', color: '#f7e05c' },
  'Authorization Header': { group: 'Sensitive Information', cn: 'Authorization 认证头', level: 'high', color: '#4fc3f7' },
  'Sensitive Field': { group: 'Sensitive Information', cn: '敏感字段(key/secret/token)', level: 'medium', color: '#f7e05c' },
  'Mobile Number Field': { group: 'Sensitive Information', cn: '手机号字段', level: 'low', color: '#66bb6a' },
  'Userinfo In Link': { group: 'Sensitive Information', cn: 'URL 内嵌用户信息', level: 'medium', color: '#66bb6a' },
  'User Identity': { group: 'Sensitive Information', cn: '前端身份存储(localStorage)', level: 'medium', color: '#66bb6a' },
  // ---- 兼容原攻击凭据标签（归入 Sensitive Information 高等级） ----
  'API Key': { group: 'Sensitive Information', cn: 'API 密钥', level: 'high', color: '#f76b6b' },
  'Bearer Token': { group: 'Sensitive Information', cn: 'Bearer 令牌', level: 'high', color: '#4fc3f7' },
  'Password': { group: 'Sensitive Information', cn: '口令/密码', level: 'high', color: '#f7a35c' },
  'Secret': { group: 'Sensitive Information', cn: '密钥/机密', level: 'high', color: '#f7e05c' },
  'Token': { group: 'Sensitive Information', cn: '令牌', level: 'high', color: '#4fc3f7' },
  'Session Cookie': { group: 'Sensitive Information', cn: '会话 Cookie', level: 'high', color: '#b388ff' },
  'Private Key': { group: 'Sensitive Information', cn: '私钥', level: 'high', color: '#ef5350' },
  'Authorization': { group: 'Sensitive Information', cn: '认证凭据', level: 'high', color: '#4fc3f7' },
  // ---- Other（其他，HaENet 原版） ----
  'Linkfinder': { group: 'Other', cn: '链接发现', level: 'info', color: '#8b98a8' },
  'Source Map': { group: 'Other', cn: 'Source Map 源码映射', level: 'low', color: '#f48fb1' },
  'Create Script': { group: 'Other', cn: '动态创建脚本', level: 'low', color: '#66bb6a' },
  'URL Schemes': { group: 'Other', cn: '自定义 URL 协议', level: 'low', color: '#f7e05c' },
  'Router Push': { group: 'Other', cn: '前端路由跳转', level: 'info', color: '#ce93d8' },
  'All URL': { group: 'Other', cn: '链接引用', level: 'info', color: '#8b98a8' },
  '302 Location': { group: 'Other', cn: '302 重定向地址', level: 'info', color: '#8b98a8' },
  'OSKeys': { group: 'Other', cn: '系统标识泄漏', level: 'medium', color: '#8b98a8' },
  // ---- Nday 线索（保留原体系，归 Maybe Vulnerability 高等级） ----
  'Nday API': { group: 'Maybe Vulnerability', cn: 'Nday 漏洞 API 路径', level: 'high', color: '#ff5252' },
  'Nday JS': { group: 'Maybe Vulnerability', cn: 'Nday 可疑 JS 引用', level: 'high', color: '#ff7043' },
  'Nday 组件': { group: 'Maybe Vulnerability', cn: 'Nday 漏洞组件/版本', level: 'high', color: '#ff5252' },
}
/** 5 组中文名（prompt 分组说明用） */
export const HAE_GROUPS: { key: HaeGroup; cn: string }[] = [
  { key: 'Fingerprint', cn: '指纹识别' },
  { key: 'Maybe Vulnerability', cn: '潜在漏洞线索' },
  { key: 'Basic Information', cn: '基础信息' },
  { key: 'Sensitive Information', cn: '敏感信息' },
  { key: 'Other', cn: '其他' },
]
/** 凭据类标签（写 Cred 节点 + 自动凭据利用意见卡的判定集合） */
export const HAE_CRED_TAGS = new Set<string>([
  'API Key', 'Bearer Token', 'Password', 'Secret', 'Token', 'Session Cookie', 'Private Key', 'Authorization',
  'Cloud Key', 'Cloud Access Key', 'Password Field', 'WeCom Key', 'JDBC Connection', 'Authorization Header',
])
/** HAE 漏洞等级色（与前端 AN_LEVEL_COLOR 同源；入图：Vuln/Api/Analysis 节点颜色标识） */
export const HAE_LEVEL_COLOR: Record<string, string> = { high: '#f76b6b', medium: '#f7a35c', low: '#f7e05c', info: '#8b98a8' }
/** 渲染 HaENet 标签清单文本（注入分析 prompt） */
export function haeTagList(): string {
  const lines: string[] = []
  for (const g of HAE_GROUPS) {
    const tags = Object.entries(HAE_TAGS).filter(([, t]) => t.group === g.key)
    lines.push(`${g.cn}(${g.key})：${tags.map(([k]) => k).join(' / ')}`)
  }
  return lines.join('\n')
}
