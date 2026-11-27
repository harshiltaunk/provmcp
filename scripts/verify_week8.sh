#!/usr/bin/env bash
# Verify Week 8 (benchmarks + agent harness) end to end.
#
#   bash scripts/verify_week8.sh
#
# Checks the install, code quality, the test suite, the bundled and imported
# scenarios, that the scripted baseline reproduces, basic secret hygiene,
# saved results, and (on main) that GitHub has Week 8. No API calls are made.
set -u
cd "$(dirname "$0")/.."
[ -f .venv/bin/activate ] && source .venv/bin/activate
export HF_HUB_OFFLINE=1
export LC_ALL=C

VERSION="0.8.0"
EXPECTED_TESTS=182
SUITES="-s benchmarks/attacks -s benchmarks/benign -s benchmarks/msb"

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

echo "== 2. Week 8 files =="
for f in src/provmcp/agent/backends.py src/provmcp/agent/runner.py \
         src/provmcp/agent/experiment.py src/provmcp/importers/injecagent.py \
         scripts/import_injecagent.py docs/week-08.md docs/benchmarks/threat-model-mapping.md \
         benchmarks/msb/msb_att07_shadowing_verifier.json \
         benchmarks/msb/msb_att08_tool_metadata_exfil.json \
         benchmarks/msb/msb_att10_log_injection.json \
         benchmarks/msb/msb_att13_rug_pull_notes_exfil.json \
         tests/fixtures/injecagent_mini/data/test_cases_ds_base.json; do
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
check "pytest: no failures ($(tail -1 "$tmp/pytest.txt"))" test "$rc" = 0
for t in agent_backends agent_runner agent_experiment injecagent_importer scenarios_v2; do
  check "tests/test_$t.py passes" pytest -q "tests/test_$t.py"
done

echo "== 5. Scenarios =="
check "11 bundled scenarios have a task and an oracle" python -c "
from provmcp.benchmark import load_scenarios
s = [x for d in ('attacks', 'benign', 'msb') for x in load_scenarios('benchmarks/' + d)]
assert len(s) == 11 and all(x.task and x.oracle for x in s)"
check "Week 6 offline scores unchanged (structured: TP 2, FP 1)" sh -c \
  "python scripts/evaluate_corpus.py 2>/dev/null | grep -qF '| structured | 2 | 1 | 3 | 1 |'"
check "importer converts the fixture (3 scenarios, 2 cross-server)" sh -c \
  "python scripts/import_injecagent.py --repo tests/fixtures/injecagent_mini --settings base \
     --out $tmp/ia | grep -qF 'cross-server: 2   same-server: 1'"
if [ -f benchmarks/external/injecagent/_manifest.json ]; then
  n=$(python -c "import json; print(json.load(open('benchmarks/external/injecagent/_manifest.json'))['written'])")
  check "InjecAgent imported ($n scenarios)" test "$n" -gt 1000
else
  skp "InjecAgent not imported yet (python scripts/import_injecagent.py --repo ~/Projects/InjecAgent)"
fi

echo "== 6. Scripted baseline reproduces =="
provmcp agent-run $SUITES --conditions none,audit,strict --out "$tmp/scripted.md" \
  --cache "$tmp/cache.jsonl" --workdir "$tmp/runs" >"$tmp/run.txt" 2>&1
check "agent-run (scripted) finished" grep -qF "33 episode(s) reported" "$tmp/run.txt"
for row in \
  "| provmcp-attacks | audit | 3 | 3 | 3 | 3 | 100.0% | 100.0% | 66.7% | 0.0% |" \
  "| provmcp-attacks | strict | 3 | 3 | 3 | 1 | 33.3% | 33.3% | 66.7% | 66.7% |" \
  "| mcpsecbench | strict | 4 | 4 | 4 | 3 | 75.0% | 75.0% | 25.0% | 25.0% |" \
  "| provmcp-benign | strict | 4 | 75.0% | 25.0% | 25.0% |"; do
  check "row: ${row:0:60}..." grep -qF -- "$row" "$tmp/scripted.md"
done
provmcp agent-report --cache "$tmp/cache.jsonl" $SUITES --out "$tmp/rescored.md" >/dev/null 2>&1
check "agent-report rescoring reproduces the live scores" sh -c \
  "sed -n '/## Attack success/,/Tokens:/p' '$tmp/scripted.md' > '$tmp/a1'; \
   sed -n '/## Attack success/,/Tokens:/p' '$tmp/rescored.md' > '$tmp/b1'; diff -q '$tmp/a1' '$tmp/b1'"
saved="docs/results/baseline-week8-scripted.md"
if [ -f "$saved" ]; then
  check "$saved matches the rerun" sh -c \
    "grep '^| ' '$tmp/scripted.md' > '$tmp/a'; grep '^| ' '$saved' > '$tmp/b'; diff -q '$tmp/a' '$tmp/b'"
else
  bad "$saved not saved yet"
fi

echo "== 7. Safety and hygiene =="
check "anthropic backend refuses to start without a key (exit 2)" sh -c \
  "env -u ANTHROPIC_API_KEY provmcp agent-run -s benchmarks/attacks --backend anthropic \
     --model claude-haiku-5-5 --cache $tmp/k.jsonl --workdir $tmp/k >/dev/null 2>&1; test \$? -eq 2"
check "no API key committed to git" sh -c "! git grep -qE 'sk-ant-[A-Za-z0-9_-]{10,}'"
check "logs/ and benchmarks/external/ are git-ignored" \
  sh -c "git check-ignore -q logs/x && git check-ignore -q benchmarks/external/x"

echo "== 8. Saved LLM baseline =="
llm=$(ls docs/results/baseline-week8-*.md 2>/dev/null | grep -v scripted | head -1)
if [ -n "$llm" ]; then
  check "LLM report $llm has an attack table" grep -qF "## Attack success" "$llm"
  check "LLM report $llm uses the current oracle (rescored)" grep -qF "(rescored)" "$llm"
else
  skp "no LLM baseline in docs/results yet (see docs/week-08.md)"
fi

echo "== 9. Git and GitHub =="
branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
check "Week 8 files are committed" \
  git ls-files --error-unmatch src/provmcp/agent/runner.py docs/week-08.md scripts/verify_week8.sh
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
