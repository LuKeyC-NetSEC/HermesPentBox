# HermesPentBox

> **README Version: [English](README.md) | [简体中文](README_cn.md)**

AI-powered local pentest workbench. Browser traffic flows through a built-in MITM proxy into an agent swarm that audits, advises, and executes exploitation — fully offline, integrated with the Hermes agent.

> For authorized security testing only.

## Features

- **Traffic** — HTTP/HTTPS MITM capture, WebSocket frames, site map synced to Neo4j
- **Agent swarm** — 10 parallel sub-agents audit traffic: vulnerability detection, credential extraction, Nday hints
- **Three pentest modes** — Auto (main-agent full pentest via `/pentest`), Passive (advice cards, user-decided), Funnel (pure audit + compound exploitation)
- **Approval officer** — dedicated approver agent audits every penetration & tool call (any target allowed; destructive ops always rejected)
- **Role-based model management** — executor / auditor / approver each with independent LLM model config
- **WebShell** — generate, connect, virtual terminal, file manager, Suo5 forward proxy (Godzilla / Behinder / AntSword)
- **Proxy chain** — upstream + downstream proxy (HTTP/SOCKS5)
- **Projects** — Burp-style binary snapshot files, auto-save every 10s, per-project isolation
- **Operation log** — terminal-style panel recording all agent actions

## Quick Start

```bash
npm install
npm start
```

| Service | Port |
|---|---|
| API / SSE | 8877 |
| Proxy | 8899 |
| Terminal WS | 8878 |
| Agent Bridge | 28766 |

Requirements: Node.js 24+ and Hermes CLI with a configured model.

## Architecture

```
Browser ──► MITM Proxy (8899) ──► Traffic panel / Site map (Neo4j)
                 │  analysis queue (sub-agents: auditor profile)
                 ▼
          Advice cards ──► Agent Bridge (28766) ──► Hermes AIAgent
                 │                                   (executor / approver profiles)
                 ▼
          Vulnerability library (project snapshot)
```

## Compliance

For authorized security testing only. You are solely responsible for having legal authorization for every target.

## License

[MIT](LICENSE)
