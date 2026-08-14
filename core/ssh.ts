/**
 * SSH 会话（ssh2）：连接 / exec 单命令 / 交互 shell（数据流接 xterm）
 */
import { Client, type ConnectConfig } from 'ssh2'

export interface SshConnectionOptions {
  host: string
  port?: number
  username: string
  password?: string
  privateKey?: string
  readyTimeout?: number
}

export class SshSession {
  private client = new Client()
  private connected = false

  connect(opts: SshConnectionOptions): Promise<void> {
    return new Promise((resolve, reject) => {
      const cfg: ConnectConfig = {
        host: opts.host,
        port: opts.port ?? 22,
        username: opts.username,
        readyTimeout: opts.readyTimeout ?? 10000,
        ...(opts.password ? { password: opts.password } : {}),
        ...(opts.privateKey ? { privateKey: opts.privateKey } : {}),
      }
      this.client.once('ready', () => {
        this.connected = true
        resolve()
      })
      this.client.once('error', reject)
      this.client.connect(cfg)
    })
  }

  /** 执行单条命令，返回完整输出 */
  exec(command: string, opts: { timeout?: number } = {}): Promise<{ code: number | null; stdout: string; stderr: string }> {
    return new Promise((resolve, reject) => {
      this.client.exec(command, (err, stream) => {
        if (err) return reject(err)
        let stdout = '', stderr = ''
        stream.on('close', (code: number | null) => resolve({ code, stdout, stderr }))
        stream.on('data', (d: Buffer) => (stdout += d.toString()))
        stream.stderr.on('data', (d: Buffer) => (stderr += d.toString()))
        if (opts.timeout) setTimeout(() => stream.close(), opts.timeout)
      })
    })
  }

  /** 交互 shell：返回双工流，接 xterm.js */
  shell(): Promise<NodeJS.ReadWriteStream> {
    return new Promise((resolve, reject) => {
      this.client.shell((err, stream) => (err ? reject(err) : resolve(stream)))
    })
  }

  close(): void {
    this.connected = false
    this.client.end()
  }

  isConnected(): boolean {
    return this.connected
  }
}
