# HermesPentBox

> **AI-Powered Local Pentest Workbench** · 中文文档见 [README_cn.md](README_cn.md)

For **authorized** testing only (SRC / bug bounty / self-hosted labs). You are responsible for having legal authorization for every target.

An all-in-one desktop workbench: built-in MITM proxy captures traffic → a swarm of sub-agents analyzes it → advice cards → one-click single-endpoint penetration verification. Runs fully local, integrating with the Hermes agent through a self-built Bridge with zero configuration.

---

## Features

| Area | Capability |
|---|---|
| **Traffic & Analysis** | HTTP/HTTPS MITM capture (8899), WebSocket frame capture, site map synced to Neo4j |
| **Agent Swarm** | 10 parallel sub-agents auto-audit traffic: vuln detection / sensitive-info extraction (HaENet tags) / Nday hints |
| **Penetration** | Advice card one-click "进行渗透", strictly single-API scope; results auto-written as VULNDOC into the vuln library |
| **Shared Intelligence** | Neo4j session graph (Host/Api/Vuln/Cred/Shell) shared across agents, same-target dedup prevents repeated attacks |
| **WebShell Manager** | Full-type generate/connect/virtual terminal/file manager/Suo5 forward proxy (Godzilla·Behinder·AntSword·Custom) |
| **Proxy Chain** | Upstream proxy + Burp-style downstream proxy (HTTP/SOCKS5, custom IP/port, persists across restarts) |
| **Browser Control** | One-click Chrome CDP / Firefox takeover, traffic auto-merged into panel; Burp-style CA trust flow |
| **Repeater / Terminal / SSH** | HTTP/HTTPS/WS multi-tab repeater, xterm virtual terminal, SSH sessions |

## Quick Start

```bash
npm install
npm start          # build + launch (first run auto-starts proxy/Bridge/CA generation)
```

- Main API: `8877` · Proxy: `8899` · Terminal WS: `8878` · Agent Bridge: `28766`
- Requirements: Node.js 24 + Hermes CLI (with a configured model)

## Architecture

```
Browser (Chrome/Firefox) ──► MITM Proxy (8899) ──► Traffic panel / Site map (Neo4j)
                                   │ analysis queue (10 sub-agents, load-balanced)
                                   ▼
                          Advice card (SSE) ──「进行渗透」──► Agent Bridge (28766)
                                   │                              │
                                   ▼                              ▼
                          Vulnerability library (VULNDOC)    Hermes AIAgent
```

## Stack

Electron · Node.js · Neo4j · esbuild · xterm.js · hermes-agent (AIAgent) · Godzilla/Behinder protocol libs

## License

For **authorized** security testing only. You are solely responsible for having legal authorization for every target.
