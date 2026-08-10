#!/usr/bin/env python3
"""
HermesPentBox 自带 Agent Bridge

TCP JSON-line 协议（参考 Hermes Agent Bridge 行为，但实现独立）：
  读一行 JSON {action, ...} → 处理 → 写一行 JSON 响应

Actions:
  ping        连通性探测
  chat        启动一轮对话（session_id 持久，复用 AIAgent 会话；后台线程跑，delta 累积）
  get_output  轮询对话输出（cursor 增量返回 delta；done=true 结束）
  steer       运行中引导：向当前 turn 的下一个工具结果注入文本（不打断，AIAgent.steer）
  redirect    重定向活跃 turn（保留工作，AIAgent.redirect）
  status      会话状态（exists/running/message_count）
  interrupt   优雅中断当前 turn（AIAgent.interrupt）
  destroy     销毁会话（释放 AIAgent）

依赖：hermes-agent 的 venv python + run_agent.AIAgent（读取 HERMES_HOME 档案配置）
启动：python pentbox_bridge.py --port 28766 --hermes-home <档案>
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import sys
import threading
import time
import traceback

PORT = 28766


def _log(*args):
    line = f"[pentbox-bridge] {' '.join(str(a) for a in args)}"
    print(line, file=sys.stderr, flush=True)
    try:
        log_path = os.environ.get("PENTBOX_BRIDGE_LOG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "pentbox_bridge.log"))
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:  # noqa: BLE001
        pass


class AgentSession:
    """一个会话 = 一个 AIAgent 实例 + 后台运行线程 + delta 缓冲"""

    def __init__(self, session_id: str, hermes_home: str):
        self.session_id = session_id
        self.hermes_home = hermes_home
        self.agent = None
        self.lock = threading.Lock()
        self.run_thread = None
        self.running = False
        self.finished = False
        self.error = None
        self.deltas: list[str] = []
        self.output = ""
        self.run_id = None
        self.started_at = None
        self.tool_events: list[dict] = []

    def _ensure_agent(self):
        if self.agent is None:
            # 延迟 import（只在需要时加载 hermes-agent 运行时）
            # 先覆盖 profile .env 到进程环境（AIAgent 从环境读 API key / base_url / provider）
            self._apply_profile_env()
            from run_agent import AIAgent

            # 复用 hermes 的 runtime 解析（config.yaml + .env → provider/model/base_url/api_key/api_mode），
            # 与 `hermes chat` 行为一致（否则 AIAgent 单独实例化时模型/端点解析缺失导致 404）
            runtime = self._resolve_runtime()
            _log("runtime:", {k: (v if k not in ("api_key",) else "***") for k, v in (runtime or {}).items()})
            self.agent = AIAgent(
                model=runtime.get("model") or "",
                api_key=runtime.get("api_key"),
                base_url=runtime.get("base_url"),
                provider=runtime.get("provider"),
                requested_provider=runtime.get("requested_provider"),
                api_mode=runtime.get("api_mode"),
                acp_command=runtime.get("command"),
                acp_args=runtime.get("args"),
                session_id=self.session_id,
                platform="cli",
                quiet_mode=True,
            )
        return self.agent

    def _resolve_runtime(self) -> dict:
        try:
            from hermes_cli.runtime_provider import resolve_runtime_provider
            return resolve_runtime_provider() or {}
        except Exception as e:  # noqa: BLE001
            _log("resolve_runtime error:", repr(e))
            _log(traceback.format_exc())
            return {}

    def _apply_profile_env(self):
        """读取 HERMES_HOME/.env 并写入 os.environ（复刻 hermes bridge worker 的 profile env overlay）"""
        try:
            env_path = os.path.join(self.hermes_home, ".env")
            if not os.path.exists(env_path):
                return
            with open(env_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    if k:
                        os.environ[k] = v
            os.environ["HERMES_HOME"] = self.hermes_home
        except Exception as e:  # noqa: BLE001
            _log("apply_profile_env error:", e)

    def start_chat(self, message) -> dict:
        with self.lock:
            if self.running:
                return {"ok": True, "run_id": self.run_id, "session_id": self.session_id, "status": "already_running"}
            if self.finished:
                # 新一轮：重置状态但复用 agent（历史在 agent 会话内）
                self.finished = False
                self.error = None
            self.running = True
            self.deltas = []
            self.output = ""
            self.tool_events = []
            self.run_id = f"run_{int(time.time() * 1000)}_{os.urandom(3).hex()}"
            self.started_at = time.time()

        def _worker():
            try:
                agent = self._ensure_agent()

                def _delta(text):
                    with self.lock:
                        self.deltas.append(text or "")
                        self.output += (text or "")

                def _tool_progress(event_type, tool_name=None, preview=None, args=None):
                    # tool.started / tool.completed 进度事件（前端显示"正在执行 X"）
                    try:
                        with self.lock:
                            self.tool_events.append({
                                "type": str(event_type or ""),
                                "tool": str(tool_name or ""),
                                "preview": str(preview or "")[:120],
                            })
                            if len(self.tool_events) > 200:
                                del self.tool_events[:50]
                    except Exception:  # noqa: BLE001
                        pass

                # 传入工具进度回调 + 已有 delta 回调
                agent.tool_progress_callback = _tool_progress
                result = agent.run_conversation(message, stream_callback=_delta)
                with self.lock:
                    final = (result or {}).get("final_response") or ""
                    if final:
                        self.output = final
                        self.deltas.append("")
                    self.finished = True
            except Exception as e:  # noqa: BLE001
                _log("chat worker error for", self.session_id, ":", repr(e))
                _log(traceback.format_exc())
                with self.lock:
                    self.error = f"{e}\n{traceback.format_exc()}"
                    self.finished = True
            finally:
                with self.lock:
                    self.running = False

        self.run_thread = threading.Thread(target=_worker, daemon=True)
        self.run_thread.start()
        return {"ok": True, "run_id": self.run_id, "session_id": self.session_id, "status": "running"}

    def get_output(self, cursor: int = 0) -> dict:
        with self.lock:
            all_delta = "".join(self.deltas)
            # cursor 语义：已交付的字符数
            delta = all_delta[cursor:] if cursor < len(all_delta) else ""
            return {
                "ok": True,
                "run_id": self.run_id,
                "session_id": self.session_id,
                "status": "error" if self.error else ("done" if self.finished else "running"),
                "delta": delta,
                "cursor": len(all_delta),
                "output": self.output if self.finished else "",
                "done": bool(self.finished),
                "error": self.error,
                "tool_events": list(self.tool_events),
            }

    def steer(self, text: str) -> dict:
        """运行中引导：复刻官方 GUI 语义——仅当本会话有活跃运行（Agent 正在跑）时 accepted。
        无活跃 turn（Agent 空闲/未启动）→ rejected（与官方 session.redirect 的 rejected 一致）。"""
        _log("steer requested for", self.session_id, ":", text[:60])
        if not text or not text.strip():
            return {"ok": True, "status": "rejected", "accepted": False, "text": text, "reason": "empty text"}
        with self.lock:
            if not self.running and not self.finished:
                # Agent 从未启动过：无活跃 turn，不可 steer
                return {"ok": True, "status": "rejected", "accepted": False, "text": text, "reason": "no active turn"}
        try:
            agent = self._ensure_agent()
            accepted = agent.steer(text)
            _log("steer accepted:", accepted)
            return {"ok": True, "status": "queued" if accepted else "rejected", "accepted": bool(accepted), "text": text}
        except Exception as e:  # noqa: BLE001
            _log("steer error:", repr(e))
            return {"ok": False, "error": str(e)}

    def redirect(self, text: str) -> dict:
        try:
            agent = self._ensure_agent()
            accepted = agent.redirect(text)
            return {"ok": True, "status": "redirected" if accepted else "rejected", "accepted": bool(accepted), "text": text}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}

    def interrupt(self, message: str = None) -> dict:
        try:
            agent = self._ensure_agent()
            agent.interrupt(message)
            return {"ok": True}
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": str(e)}

    def status(self) -> dict:
        with self.lock:
            return {
                "ok": True,
                "exists": True,
                "running": self.running,
                "current_run_id": self.run_id,
                "message_count": len(self.deltas),
                "can_steer": bool(self.running),
            }

    def destroy(self) -> dict:
        try:
            if self.agent is not None:
                try:
                    self.agent.interrupt("destroyed")
                except Exception:  # noqa: BLE001
                    pass
        finally:
            with self.lock:
                self.running = False
                self.finished = True
        return {"ok": True}


class PentboxBridge:
    def __init__(self, hermes_home: str, port: int):
        self.hermes_home = hermes_home
        self.port = port
        self.sessions: dict[str, AgentSession] = {}
        self.sessions_lock = threading.Lock()

    def _get_session(self, session_id: str) -> AgentSession:
        with self.sessions_lock:
            if session_id not in self.sessions:
                self.sessions[session_id] = AgentSession(session_id, self.hermes_home)
            return self.sessions[session_id]

    def handle(self, req: dict) -> dict:
        action = req.get("action", "")
        sid = str(req.get("session_id") or "")
        text = str(req.get("text") or "")

        if action == "ping":
            return {"ok": True, "pong": True, "time": time.time(), "mode": "pentbox-bridge", "sessions": len(self.sessions)}

        if action == "chat":
            if not sid:
                return {"ok": False, "error": "session_id required"}
            return self._get_session(sid).start_chat(req.get("message"))

        if action == "get_output":
            sid = str(req.get("session_id") or "")
            # 兼容：仅传 run_id 时按 run_id 反查 session
            if not sid:
                run_id = str(req.get("run_id") or "")
                for _s in list(self.sessions.values()):
                    if _s.run_id == run_id:
                        sid = _s.session_id
                        break
            if not sid:
                return {"ok": False, "error": "session_id required"}
            cursor = int(req.get("cursor") or 0)
            return self._get_session(sid).get_output(cursor)

        if action == "steer":
            if not sid or not text:
                return {"ok": False, "error": "session_id and text required"}
            return self._get_session(sid).steer(text)

        if action == "redirect":
            if not sid or not text:
                return {"ok": False, "error": "session_id and text required"}
            return self._get_session(sid).redirect(text)

        if action == "status":
            if not sid:
                return {"ok": False, "error": "session_id required"}
            return self._get_session(sid).status()

        if action == "interrupt":
            if not sid:
                return {"ok": False, "error": "session_id required"}
            return self._get_session(sid).interrupt(req.get("message"))

        if action == "destroy":
            if not sid:
                return {"ok": False, "error": "session_id required"}
            with self.sessions_lock:
                self.sessions.pop(sid, None)
            return {"ok": True}

        return {"ok": False, "error": f"unknown action: {action}"}

    def serve(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", self.port))
        srv.listen(16)
        _log(f"listening on 127.0.0.1:{self.port}")
        while True:
            try:
                conn, _addr = srv.accept()
                conn.settimeout(300)
                threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()
            except Exception:  # noqa: BLE001
                _log("accept error:", traceback.format_exc())

    def _handle_conn(self, conn: socket.socket):
        try:
            buf = b""
            while True:
                data = conn.recv(65536)
                if not data:
                    break
                buf += data
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    line = line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    try:
                        req = json.loads(line)
                    except Exception:  # noqa: BLE001
                        conn.sendall((json.dumps({"ok": False, "error": "invalid json"}) + "\n").encode())
                        continue
                    resp = self.handle(req)
                    conn.sendall((json.dumps(resp) + "\n").encode())
        except Exception:  # noqa: BLE001
            _log("conn error:", traceback.format_exc())
        finally:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass


def main():
    parser = argparse.ArgumentParser(description="HermesPentBox Agent Bridge")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--hermes-home", default="")
    args = parser.parse_args()

    home = args.hermes_home or os.environ.get("HERMES_HOME", "")
    if not home:
        home = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "hermes", "profiles", "hermespentbox")
    os.environ["HERMES_HOME"] = home

    # hermes-agent 运行时入 sys.path（run_agent 依赖）
    agent_root = os.environ.get("HERMES_AGENT_ROOT", "")
    if agent_root and agent_root not in sys.path:
        sys.path.insert(0, agent_root)

    bridge = PentboxBridge(home, args.port)
    bridge.serve()


if __name__ == "__main__":
    main()
