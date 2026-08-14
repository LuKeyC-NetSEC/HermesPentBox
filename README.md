# HermesPentBox

AI-powered local pentest workbench. Browser traffic flows through a built-in MITM proxy into an agent swarm that analyzes, advises, and executes single-endpoint exploitation — fully offline, integrated with the Hermes agent.

> For authorized security testing only.

## Features

- **Traffic** — HTTP/HTTPS MITM capture, WebSocket frames, site map synced to Neo4j
- **Analysis** — 10 parallel sub-agents audit traffic: vulnerability detection, credential extraction, Nday hints
- **Exploitation** — one-click single-endpoint verification; results auto-written to the vulnerability library
- **Shared intelligence** — Neo4j session graph (hosts/APIs/vulns/credentials/shells) shared across agents with same-target dedup
- **WebShell** — generate, connect, virtual terminal, file manager, Suo5 forward proxy (Godzilla / Behinder / AntSword / custom)
- **Proxy chain** — upstream proxy + Burp-style downstream proxy (HTTP/SOCKS5)
- **Browser control** — one-click Chrome CDP / Firefox takeover
- **Projects** — Burp-style project files: binary snapshots with auto-save, project management, per-project data isolation

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
                 │  analysis queue (10 sub-agents)
                 ▼
          Advice cards ──► Agent Bridge (28766) ──► Hermes AIAgent
                 │
                 ▼
          Vulnerability library (project snapshot)
```

## Stack

Electron · Node.js · esbuild · Neo4j · xterm.js · Hermes Agent · V8 binary project snapshots

## Compliance

For authorized security testing only (SRC / bug bounty / self-hosted labs). You are solely responsible for having legal authorization for every target.
