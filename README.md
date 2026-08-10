# HermesPentBox — AI Pentest Workbench

> **Language**: English | [中文文档](README_cn.md)

An Electron-based desktop penetration testing workbench: built-in MITM traffic proxy, browser control (Chrome CDP / Firefox), and a swarm of parallel sub-agents for traffic analysis and targeted API exploitation — all local, zero-config integration with the Hermes agent via a self-built Agent Bridge.

> For **authorized** testing only (client contracts / SRC bug bounty / self-hosted labs). You are responsible for having legal authorization for every target.

---

## Features

- **MITM traffic proxy** (default port 8899): HTTP/HTTPS transparent proxy with built-in CA (`PentBox MITM Root CA`), WebSocket frame-level capture
- **Browser control**: Chrome CDP (port 9334) / Firefox one-click takeover, browser traffic auto-merges into the traffic panel
- **Sub-agent swarm analysis**: 10 parallel sub-agent slots, traffic load-balanced for vuln detection / sensitive-info extraction / Nday hints
- **Penetration advice cards**: sub-agents push advice cards; clicking "进行渗透" adopts the advice for that **single API** (strict single-URL scope, no site-wide expansion)
- **Self-built Agent Bridge** (`core/pentbox_bridge.py`): TCP JSON-line service driving the Hermes `AIAgent` directly — no external project dependency. All chat / analysis / penetration / steer run through it
- **Streaming chat**: main agent conversation streams SSE deltas (typewriter effect) with cross-turn session persistence
- **Steer (live guidance, non-interrupting)**: while an agent is running, typing in the composer switches the button to **Steer** — inject guidance into the running turn without stopping it (official-GUI semantics: accepted only when a turn is active, rejected when idle). Available for both the main agent and sub-agent windows
- **Tool progress feedback**: while the agent calls tools, the UI shows "⚙ executing X" instead of a bare spinner
- **Vulnerability library**: penetration results auto-written as structured VULNDOC (title / severity / reproduction / raw request-response); result card replaces the advice card and persists
- **Structured global intelligence**: multi-agent battlefield sharing — digests are structured by kind (`vuln` / `cred` / `nday` / `penetrating` / `penetrated` / `cancelled` / `note`) with persistent vs. rolling layers (credentials / findings / cancellations never age out; analysis streams rotate in a 20-entry window). Credentials auto-generate a "凭据利用" advice card; main-agent target instructions flow back into the digest; cancellation records act as downgrade signals
- **Dedup**: unified `normalizeTargetKey` (host + full path + query) across card-push / pre-penetration / result-write; `penetratingKeys` prevents concurrent double-penetration of the same target
- **Repeater**: HTTP/HTTPS/WS auto protocol detection, multi-tab, Burp-style UX
- **Site map**: aggregated traffic view grouped by domain/path
- **Per-agent chat window**: talk to an individual sub-agent to inspect details

## Architecture

```
Browser (Chrome CDP / Firefox)
   │ traffic
   ▼
MITM Proxy (8899) ──► Traffic panel / Site map
   │ analysis queue
   ▼
10 × Sub-agents (Agent Bridge, load-balanced)
   │ advice (SSE)
   ▼
Advice card ──「进行渗透」──► Agent Bridge (AIAgent)
   │                            chat / get_output / steer / interrupt
   ▼
Vulnerability library (VULNDOC) / Global intelligence digest
```

- **Main API**: 8877 (HTTP + SSE event stream)
- **Terminal WS**: 8878
- **Agent Bridge**: 28766 (self-built TCP JSON-line service, auto-started, uses hermes-agent's `AIAgent` + profile `hermespentbox`)

## Quick Start

### Requirements

- Node.js 24 (LTS)
- Hermes CLI (`hermes` on PATH) with a configured model provider

### Install & Run

```bash
npm install
npm run build     # esbuild bundle electron/main.ts → out/main.cjs
npm start         # build + launch
# or directly:
npx electron .
```

First launch auto-starts: MITM proxy (8899), CA certificate generation, and the self-built Agent Bridge (28766).

### Tests

```bash
node node_modules/tsx/dist/cli.mjs core/proxy.test.ts
node node_modules/tsx/dist/cli.mjs core/api.test.ts
```

> Tests bind ports (e.g. 8899) — quit the running app first.

## Configuration

| Item | Default | Description |
|---|---|---|
| API port | 8877 | Main HTTP API + SSE |
| Proxy port | 8899 | MITM proxy |
| CDP port | 9334 | Chrome remote debugging |
| Terminal WS | 8878 | Terminal panel |
| Agent Bridge | 28766 | Self-built TCP bridge (auto-started) |
| Upstream proxy | 7890 | Optional (CN network) |
| Agent slots | 10 | Parallel analysis concurrency |

## Directory Structure

```
electron/main.ts       app entry (Electron main process)
core/proxy.ts          MITM proxy engine (CA generation/injection)
core/api.ts            main API server (traffic/analysis/pentest/vuln-lib/SSE/global-intel)
core/bridge.ts         Agent Bridge client (TCP JSON-line: chat/steer/get_output/status/interrupt)
core/pentbox_bridge.py self-built Agent Bridge server (drives hermes-agent AIAgent)
core/browser.ts        Chrome CDP control
core/firefox.ts        Firefox control
core/ssh.ts            SSH terminal
core/persona.ts        sub-agent persona & prompts
ui/app.js              frontend (traffic panel / advice cards / vuln lib / repeater / streaming chat / steer)
assets/                static assets & skill packs
```

## FAQ

- **EADDRINUSE**: leftover process holding a port — `taskkill /F /IM electron.exe`, clean PIDs per port, then relaunch
- **curl can't go through the proxy**: Windows schannel is incompatible with MITM — use `python urllib` + trust the PentBox CA
- **Sub-agent spinning for a long time**: penetration is a long-running task (multi-step verification is normal); the UI now shows tool progress and an elapsed-work timer instead of a bare spinner. If it truly hangs, click cancel
- **Steer rejected**: guidance is only accepted while the target agent has an active run; when idle the button falls back to Send / Stop
