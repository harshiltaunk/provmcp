#!/usr/bin/env bash
# Live demo: ProvMCP stops the cd-003 exfiltration attack in a running daemon.
#
#   bash scripts/demo_live_attack.sh           # narrated; offers to approve if run in a terminal
#   bash scripts/demo_live_attack.sh --check   # silent self-test, exit 0 on success
#
# Starts `provmcp run -c configs/demo-attack.toml` (port 7338), replays the attack
# over HTTP and through the daemon bridge, shows the approval queue and audit
# log, and proves the email server never received the held call.
set -u
cd "$(dirname "$0")/.."
[ -f .venv/bin/activate ] && source .venv/bin/activate

CHECK=0; [ "${1:-}" = "--check" ] && CHECK=1
CONFIG="configs/demo-attack.toml"
URL="http://127.0.0.1:7338"
SCENARIO="benchmarks/attacks/cd_003_recased_address_exfiltration.json"
RECEIVED="logs/demo-email-received.jsonl"

say()  { [ "$CHECK" -eq 1 ] || printf '%s\n' "$*"; }
step() { [ "$CHECK" -eq 1 ] || printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
die()  { echo "DEMO FAILED: $*" >&2; exit 1; }
rpc()  { curl -s -X POST "$URL/mcp/$1" -H 'content-type: application/json' -d "$2"; }
json() { python -c "import json,sys; d=json.load(sys.stdin); print($1)"; }
received() { [ -f "$RECEIVED" ] && wc -l < "$RECEIVED" | tr -d ' ' || echo 0; }

if curl -s "$URL/health" >/dev/null 2>&1; then
  die "something is already listening on $URL; stop it first (lsof -ti :7338 | xargs kill)"
fi

mkdir -p logs
rm -f logs/demo-audit.jsonl logs/demo-approvals.json "$RECEIVED"
step "Starting ProvMCP daemon ($CONFIG)"
provmcp run -c "$CONFIG" --log-level warning >logs/demo-daemon.log 2>&1 &
DAEMON=$!
trap 'kill $DAEMON 2>/dev/null; wait $DAEMON 2>/dev/null' EXIT
for _ in $(seq 1 50); do curl -s "$URL/health" >/dev/null 2>&1 && break; sleep 0.2; done
curl -s "$URL/health" >/dev/null 2>&1 || die "daemon did not start; see logs/demo-daemon.log"
say "daemon up: $(curl -s "$URL/health")"

for sid in calendar email; do
  rpc "$sid" '{"jsonrpc":"2.0","id":0,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"demo","version":"0"}}}' >/dev/null
  rpc "$sid" '{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}' >/dev/null
done

step "1. The assistant reads the next calendar event (poisoned)"
cal=$(rpc calendar '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_next_event"}}')
say "$(json "d['result']['content'][0]['text']" <<<"$cal")"

step "2. Following the injected note, it tries to email the roster to the attacker"
send_params=$(python -c "import json; print(json.dumps(json.load(open('$SCENARIO'))['trace'][1]['params']))")
send='{"jsonrpc":"2.0","id":2,"method":"tools/call","params":'"$send_params"'}'
held=$(rpc email "$send")
is_error=$(json "d['result']['isError']" <<<"$held")
action=$(json "d['result']['_meta']['provmcp']['action']" <<<"$held")
approval=$(json "d['result']['_meta']['provmcp']['approval_id']" <<<"$held")
say "ProvMCP answered the assistant with:"
say "  $(json "d['result']['content'][0]['text']" <<<"$held")"
[ "$is_error" = "True" ] && [ "$action" = "warn" ] || die "email call was not held (action=$action)"
[ "$(received)" = "0" ] || die "email server received the held call"
say "email server received: $(received) call(s)"

step "3. Same attack through the daemon bridge (what Claude Desktop launches)"
bridge_out=$(printf '%s\n' "$send" | provmcp bridge --via "$URL" --server email 2>/dev/null)
bridge_err=$(json "d['result']['isError']" <<<"$bridge_out")
[ "$bridge_err" = "True" ] || die "bridge did not relay the held result: $bridge_out"
say "bridge relayed the held result (isError=$bridge_err); email received: $(received)"

step "4. Approval queue (out-of-band; the assistant cannot approve)"
[ "$CHECK" -eq 1 ] || provmcp approvals list -c "$CONFIG"
status=$(json "d.get('$approval', {}).get('status')" < logs/demo-approvals.json)
[ "$status" = "pending" ] || die "approval $approval is not pending (status=$status)"

step "5. Audit log"
[ "$CHECK" -eq 1 ] || provmcp audit -c "$CONFIG" -n 5
[ "$(wc -l < logs/demo-audit.jsonl | tr -d ' ')" -ge 2 ] || die "audit log missing decisions"

if [ "$CHECK" -eq 0 ] && [ -t 0 ]; then
  step "6. Approve it yourself?"
  read -r -p "Run 'provmcp approvals approve $approval' now (you will be asked to confirm)? [y/N] " answer
  if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
    provmcp approvals approve "$approval" -c "$CONFIG"
    retry=$(rpc email "$send")
    say "retry result: $(json "d['result']" <<<"$retry")"
    say "email server received: $(received) call(s)  (exactly one, approvals are single-use)"
    again=$(rpc email "$send")
    say "retry again: $(json "d['result']['_meta']['provmcp']['action']" <<<"$again") (needs a new approval)"
  fi
fi

say ""
say "Demo complete. Held: yes. Reached email server: $(received). Approval: $approval."
[ "$CHECK" -eq 1 ] && echo "demo check: PASS"
exit 0
