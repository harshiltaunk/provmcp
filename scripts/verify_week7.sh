#!/usr/bin/env bash
# Verify Week 7 (live enforcement) end to end.
#
#   bash scripts/verify_week7.sh
#
# Checks the install, code quality, the full test suite, the CLI's security
# behaviour, the live attack demo, and (on main) that GitHub has Week 7.
# Port 7338 must be free. Takes about a minute.
set -u
cd "$(dirname "$0")/.."
[ -f .venv/bin/activate ] && source .venv/bin/activate
export HF_HUB_OFFLINE=1
export LC_ALL=C

VERSION="0.7.0"
EXPECTED_TESTS=132
DEMO="configs/demo-attack.toml"

pass=0; fail=0; skip=0
ok()    { echo "  PASS  $1"; pass=$((pass+1)); }
bad()   { echo "  FAIL  $1"; fail=$((fail+1)); }
skp()   { echo "  SKIP  $1"; skip=$((skip+1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "== 1. Install =="
check "python is 3.11 or newer" python -c "import sys; assert sys.version_info >= (3, 11)"
check "provmcp version is $VERSION" sh -c "provmcp version | grep -qF '$VERSION'"
check "provmcp doctor" provmcp doctor

echo "== 2. Week 7 files =="
for f in src/provmcp/inspector.py src/provmcp/approvals.py src/provmcp/audit.py \
         examples/dummy_server/scripted_server.py "$DEMO" \
         scripts/demo_live_attack.sh docs/week-07.md \
         tests/test_inspector.py tests/test_approvals_and_audit.py \
         tests/test_proxy_enforcement.py tests/test_daemon_bridge.py \
         tests/test_live_enforcement.py; do
  check "$f" test -s "$f"
done

echo "== 3. Code quality =="
check "ruff check"          ruff check src tests scripts examples
check "ruff format --check" ruff format --check src tests scripts examples
check "mypy src (strict)"   mypy src

echo "== 4. Tests =="
collected=$(pytest --collect-only -q 2>/dev/null | grep -Eo '^[0-9]+ tests? collected' | grep -Eo '^[0-9]+')
check "pytest collects $EXPECTED_TESTS tests (found ${collected:-0})" test "${collected:-0}" = "$EXPECTED_TESTS"
pytest -q >"$tmp/pytest.txt" 2>&1; rc=$?
summary=$(tail -1 "$tmp/pytest.txt")
check "pytest: no failures ($summary)" test "$rc" = 0
for t in inspector approvals_and_audit proxy_enforcement daemon_bridge live_enforcement server; do
  check "tests/test_$t.py passes" pytest -q "tests/test_$t.py"
done

echo "== 5. Security behaviour of the CLI =="
check "approve refuses without a terminal (exit 2)" \
  sh -c "provmcp approvals approve deadbeef -c $DEMO </dev/null; test \$? -eq 2"
check "deny refuses without a terminal (exit 2)" \
  sh -c "provmcp approvals deny deadbeef -c $DEMO </dev/null; test \$? -eq 2"
check "Claude config defaults to daemon mode" \
  sh -c "provmcp export-claude-config -c configs/dev.toml | grep -qF -- '--via'"
cat >"$tmp/bad.toml" <<'EOF'
[[proxy.pair_policies]]
source = "calendar"
target = "nowhere"
policy = "strict"
EOF
check "config rejects a pair policy naming an unknown server" \
  sh -c "provmcp list-servers -c $tmp/bad.toml 2>&1 | grep -q 'unknown server'"

echo "== 6. Live attack demo (cd-003 against a running daemon) =="
if lsof -ti :7338 >/dev/null 2>&1; then
  bad "port 7338 is busy; stop it with: lsof -ti :7338 | xargs kill"
else
  check "demo_live_attack.sh --check" bash scripts/demo_live_attack.sh --check
  check "email server received 0 calls" \
    sh -c "test ! -s logs/demo-email-received.jsonl"
  check "one approval is pending" \
    python -c "import json; d=json.load(open('logs/demo-approvals.json')); \
assert [a['status'] for a in d.values()] == ['pending']"
  check "audit log recorded warn decisions" \
    python -c "import json; e=[json.loads(l) for l in open('logs/demo-audit.jsonl')]; \
assert e and all(x['action'] == 'warn' for x in e)"
  check "daemon released port 7338" sh -c "sleep 1; ! lsof -ti :7338"
fi

echo "== 7. Git and GitHub =="
branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
check "Week 7 files are committed" \
  git ls-files --error-unmatch src/provmcp/inspector.py docs/week-07.md scripts/verify_week7.sh
check "working tree is clean" sh -c "test -z \"\$(git status --porcelain)\""
if [ "$branch" = "main" ]; then
  git fetch -q origin 2>/dev/null
  check "origin/main has version $VERSION" \
    sh -c "git show origin/main:pyproject.toml | grep -qF 'version = \"$VERSION\"'"
  check "local main matches origin/main" \
    sh -c "test \"\$(git rev-parse HEAD)\" = \"\$(git rev-parse origin/main)\""
else
  skp "GitHub checks (on branch '$branch'; rerun on main after merging)"
fi

echo
echo "Results: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
