#!/usr/bin/env bash
# 为 pohoc/sa-token 建立 tag 推送门禁（一次性配置，需 repo admin 权限 token）：
#   1. v* tag 指向的提交必须存在名为 "CI green gate" 且 conclusion=success 的检查
#   2. 禁止删除/更新已存在的 v* tag（防止重指导致 Packagist 版本固化）
#
# 用法: GH_TOKEN=ghp_xxx ./scripts/setup-tag-protection.sh
set -euo pipefail

: "${GH_TOKEN:?需要 GH_TOKEN 环境变量（需 repo admin 权限）}"
REPO="${REPO:-pohoc/sa-token}"
GATE_CONTEXT="${GATE_CONTEXT:-CI green gate}"

payload=$(cat <<JSON
{
  "name": "release-tags-require-green-ci",
  "target": "tag",
  "enforcement": "active",
  "bypass": "none",
  "conditions": {
    "ref_name": {
      "include": ["refs/tags/v*"],
      "exclude": []
    }
  },
  "rules": [
    {
      "type": "required_status_checks",
      "parameters": {
        "strict_required_status_checks_policy": false,
        "required_status_checks": [
          { "context": "$GATE_CONTEXT" }
        ]
      }
    },
    { "type": "deletion", "parameters": {} },
    { "type": "update", "parameters": {} }
  ]
}
JSON
)

# 已存在同名 ruleset 则更新，否则创建
EXISTING=$(curl -sf --max-time 30 \
  -H "Authorization: Bearer $GH_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/$REPO/rulesets" \
  | python3 -c '
import json, sys
rs = [r["id"] for r in json.load(sys.stdin) if r.get("name") == "release-tags-require-green-ci"]
print(rs[0] if rs else "")
') || true

if [ -n "${EXISTING:-}" ]; then
  HTTP=$(curl -s -o /tmp/ruleset-resp.json -w "%{http_code}" -X PUT \
    -H "Authorization: Bearer $GH_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$REPO/rulesets/$EXISTING" \
    -d "$payload")
else
  HTTP=$(curl -s -o /tmp/ruleset-resp.json -w "%{http_code}" -X POST \
    -H "Authorization: Bearer $GH_TOKEN" \
    -H "Accept: application/vnd.github+json" \
    "https://api.github.com/repos/$REPO/rulesets" \
    -d "$payload")
fi

if [ "$HTTP" = "201" ] || [ "$HTTP" = "200" ]; then
  ID=$(python3 -c 'import json;print(json.load(open("/tmp/ruleset-resp.json"))["id"])')
  echo "✓ ruleset 已生效 (id=$ID)：v* tag 须 CI green gate 通过才可推送，且禁止删除/重指"
else
  echo "✗ 配置失败 HTTP $HTTP：" >&2
  cat /tmp/ruleset-resp.json >&2
  exit 1
fi
