/**
 * Hermes Agent Bridge 客户端（TCP line-protocol）
 * 参考 hermes-studio packages/server/src/services/hermes/agent-bridge/client.ts
 * 通道：TCP 连接 → 发 JSON 行 {action, ...} → 读一行 JSON 响应
 * 用途：主 Agent 对话（action:chat + get_output 轮询流式）+ 运行中引导（action:steer，不打断注入下一工具结果）
 */
import { createConnection, type Socket } from 'node:net'

export interface AgentBridgeOptions {
  host?: string
  port?: number
  timeoutMs?: number
  connectRetryMs?: number
}

export interface AgentBridgeChatStarted {
  ok: true
  run_id: string
  session_id: string
  status: string
}

export interface AgentBridgeOutput {
  ok: true
  run_id: string
  session_id: string
  status: string
  delta?: string
  cursor: number
  output?: string
  done: boolean
  error?: string | null
  events?: unknown[]
  tool_events?: { type: string; tool: string; preview: string }[]
  event_cursor: number
}

export interface AgentBridgeSteerResult {
  ok: true
  status?: string
  accepted?: boolean
  text?: string
}

export interface AgentBridgeStatusResult {
  ok: true
  exists?: boolean
  running?: boolean
  current_run_id?: string | null
  message_count?: number
  [k: string]: unknown
}

export class AgentBridgeClient {
  readonly host: string
  readonly port: number
  readonly timeoutMs: number

  constructor(options: AgentBridgeOptions = {}) {
    this.host = options.host ?? '127.0.0.1'
    this.port = options.port ?? 28766
    this.timeoutMs = options.timeoutMs ?? 120000
  }

  private connectSocket(): Promise<Socket> {
    return new Promise((resolve, reject) => {
      const socket = createConnection({ host: this.host, port: this.port })
      socket.setNoDelay(true)
      const cleanup = () => {
        socket.off('connect', onConnect)
        socket.off('error', onError)
      }
      const onConnect = () => { cleanup(); resolve(socket) }
      const onError = (err: Error) => { cleanup(); socket.destroy(); reject(err) }
      socket.once('connect', onConnect)
      socket.once('error', onError)
    })
  }

  /** 发一条 JSON-RPC 行，读一行 JSON 响应（line-protocol） */
  request<T = Record<string, unknown>>(payload: Record<string, unknown>, timeoutMs?: number): Promise<T> {
    const t = timeoutMs ?? this.timeoutMs
    return new Promise<T>((resolve, reject) => {
      this.connectSocket()
        .then((socket) => {
          let buffer = ''
          const timeout = setTimeout(() => {
            cleanup()
            socket.destroy()
            reject(new Error(`Agent bridge 请求超时（${t}ms）: ${String(payload.action)}`))
          }, t)
          const cleanup = () => {
            clearTimeout(timeout)
            socket.off('data', onData)
            socket.off('error', onError)
            socket.off('end', onEnd)
            socket.off('close', onClose)
          }
          const finish = (line: string) => {
            cleanup()
            socket.destroy()
            try { resolve(JSON.parse(line) as T) } catch (e) { reject(e) }
          }
          const onData = (chunk: Buffer) => {
            buffer += chunk.toString('utf8')
            const idx = buffer.indexOf('\n')
            if (idx >= 0) finish(buffer.slice(0, idx))
          }
          const onError = (err: Error) => { cleanup(); socket.destroy(); reject(err) }
          const onEnd = () => { const line = buffer.trim(); if (line) finish(line) }
          const onClose = () => { if (!buffer.trim()) { cleanup(); reject(new Error('Agent bridge 连接关闭且无响应')) } }
          socket.on('data', onData)
          socket.once('error', onError)
          socket.once('end', onEnd)
          socket.once('close', onClose)
          socket.write(`${JSON.stringify(payload)}\n`)
        })
        .catch((e) => reject(e))
    })
  }

  ping(): Promise<{ ok: true; pong: boolean }> {
    return this.request({ action: 'ping' }, 5000)
  }

  /** 启动一轮对话（异步：立即返回 run_id；输出经 get_output 轮询） */
  chat(sessionId: string, message: string | unknown[], profile?: string): Promise<AgentBridgeChatStarted> {
    return this.request<AgentBridgeChatStarted>({
      action: 'chat',
      session_id: sessionId,
      message,
      ...(profile ? { profile } : {}),
    })
  }

  /** 轮询一轮对话的输出（cursor 增量增量流式 delta） */
  getOutput(runId: string, cursor = 0, eventCursor = 0): Promise<AgentBridgeOutput> {
    return this.request<AgentBridgeOutput>({ action: 'get_output', run_id: runId, cursor, event_cursor: eventCursor }, 10000)
  }

  /** 运行中引导：向当前运行 turn 的下一个工具结果注入消息（不打断，无中断） */
  steer(sessionId: string, text: string, profile?: string): Promise<AgentBridgeSteerResult> {
    return this.request<AgentBridgeSteerResult>({
      action: 'steer',
      session_id: sessionId,
      text,
      ...(profile ? { profile } : {}),
    }, 10000)
  }

  status(sessionId: string, profile?: string): Promise<AgentBridgeStatusResult> {
    return this.request<AgentBridgeStatusResult>({
      action: 'status',
      session_id: sessionId,
      ...(profile ? { profile } : {}),
    }, 10000)
  }

  interrupt(sessionId: string, message?: string, profile?: string): Promise<Record<string, unknown>> {
    return this.request({ action: 'interrupt', session_id: sessionId, ...(message ? { message } : {}), ...(profile ? { profile } : {}) }, 10000)
  }

  destroy(sessionId: string, profile?: string): Promise<Record<string, unknown>> {
    return this.request({ action: 'destroy', session_id: sessionId, ...(profile ? { profile } : {}) }, 10000)
  }
}
