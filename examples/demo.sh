#!/usr/bin/env bash
# Delegation demo: a human grants an agent "tools.*", the agent hands a sub-agent
# "tools.search" only, and a demo tool service enforces it.
#
#   pip install "invaris-agentauth[server]"
#   bash examples/demo.sh          # from a clone of the repo; needs curl
#
# Everything runs in a temporary directory: a registry on 127.0.0.1:8000 and
# examples/tool_service.py on 127.0.0.1:9000. Both are stopped on exit.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="$(mktemp -d)"
export AGENTAUTH_HOME="$WORK/keys"
cd "$WORK"
cleanup() { kill $(jobs -p) 2>/dev/null || true; wait 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

wait_for() { for _ in $(seq 80); do curl -sf "$1" >/dev/null && return 0; sleep 0.25; done; echo "timed out waiting for $1" >&2; exit 1; }
show() { printf '\n$ %s\n' "$*"; "$@" 2>&1 | grep -v '^warning: key files are stored unencrypted' || true; }
# call NAME METHOD PATH JSON: sign with NAME's key and grant, then send it with curl
call() {
  local hdrs auth grant
  hdrs=$(agentauth sign "$1" "$2" "http://127.0.0.1:9000$3" --data "$4" --grant "$1.grant")
  auth=$(sed -n 's/^Authorization: //p' <<<"$hdrs"); grant=$(sed -n 's/^AgentGrant: //p' <<<"$hdrs")
  printf '\n$ call %s %s %s\n' "$1" "$2" "$3"
  curl -s -w '  -> HTTP %{http_code}\n' -X "$2" -H 'Content-Type: application/json' \
       -H "Authorization: $auth" -H "AgentGrant: $grant" --data "$4" "http://127.0.0.1:9000$3"
}

agentauth serve --db "$WORK/registry.db" >"$WORK/registry.log" 2>&1 &
wait_for http://127.0.0.1:8000/readyz

for args in "arunima --meta kind=human" "researcher --controller arunima" "summarizer --controller researcher"; do
  agentauth init $args >/dev/null 2>&1
done
ARUNIMA=$(agentauth show arunima | python3 -c 'import json,sys; print(json.load(sys.stdin)["did"])')
python3 "$HERE/tool_service.py" --trust "$ARUNIMA" --port 9000 >"$WORK/service.log" 2>&1 &
wait_for http://127.0.0.1:9000/healthz
echo "registry :8000 and tool service :9000 up; identities: arunima (human) -> researcher -> summarizer"

show agentauth grant arunima researcher --scope 'tools.*' --aud 127.0.0.1:9000 --depth 1 -o researcher.grant
show agentauth grant researcher summarizer --scope tools.search --aud 127.0.0.1:9000 --parent researcher.grant -o summarizer.grant

call summarizer POST /search '{"q":"agent identity"}'
call summarizer POST /send-email '{"to":"boss@example.com"}'
show agentauth grant summarizer researcher --scope tools.search --aud 127.0.0.1:9000 --parent summarizer.grant

ROOT=$(agentauth inspect researcher.grant | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')
show agentauth revoke arunima "$ROOT"
echo "# the service caches 'not revoked' answers for 5 s; waiting 6 s"
sleep 6
call summarizer POST /search '{"q":"agent identity"}'
