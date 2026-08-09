import { SshSession } from './ssh.ts'
// 真连用户 Kali（只读命令，验证 exec 链路）
const s = new SshSession()
await s.connect({ host: '192.168.6.133', port: 22, username: 'root', password: '123456', readyTimeout: 8000 })
const r = await s.exec('echo PENTBOX_SSH_OK && whoami && uname -s')
console.log('code:', r.code)
console.log('stdout:', r.stdout.trim())
console.log('stderr:', r.stderr.trim() || '(empty)')
s.close()
console.log(r.stdout.includes('PENTBOX_SSH_OK') ? 'SSH EXEC ✓' : 'SSH FAIL')
process.exit(0)
