#!/usr/bin/env bash
# Verify Week 11 (performance overhead) end to end.
#
#   bash scripts/verify_week11.sh
#
# Runs a quick benchmark (about a minute), checks the cache and the store
# bound, and checks the saved full-run report. No API calls.
set -u
cd "$(dirname "$0")/.."
[ -f .venv/bin/activate ] && source .venv/bin/activate
export HF_HUB_OFFLINE=1
export LC_ALL=C

VERSION="0.11.0"
EXPECTED_TESTS=231

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

echo "== 2. Week 11 files =="
for f in src/provmcp/perf.py scripts/bench_week11.py docs/week-11.md tests/test_week11_performance.py; do
  check "$f" test -s "$f"
done

echo "== 3. Code quality =="
check "ruff check"          ruff check src tests scripts examples
check "ruff format --check" ruff format --check src tests scripts examples
check "mypy src (strict)"   mypy src

echo "== 4. Tests =="
collected=$(pytest --collect-only -q 2>/dev/null | grep -Eo '^[0-9]+ tests? collected' | grep -Eo '^[0-9]+')
check "pytest collects $EXPECTED_TESTS tests (found ${collected:-0})" test "${collected:-0}" = "$EXPECTED_TESTS"
pytest -q -rs >"$tmp/pytest.txt" 2>&1; rc=$?
check "pytest: no failures ($(tail -1 "$tmp/pytest.txt"))" test "$rc" = 0
check "the live-daemon bound test ran (not skipped)" sh -c "! grep -q 'SKIPPED.*fastapi' '$tmp/pytest.txt'"

echo "== 5. Quick benchmark =="
python scripts/bench_week11.py --quick --skip-embedding --out "$tmp/p.md" --json "$tmp/p.json" \
  --figures "$tmp/fig" >"$tmp/run.txt" 2>&1
check "quick benchmark finished" test -s "$tmp/p.json"
check "cache makes the default detector faster at 100 payloads" python -c "
import json
rows = json.load(open('$tmp/p.json'))['detectors']
get = lambda c: [r for r in rows if r['detector'] == '0.9.0 default' and r['cached'] == c and r['store_size'] == 100][0]['p50']
assert get(True) * 3 < get(False), (get(True), get(False))"
check "ProvMCP adds under 50 ms at p95 (stdio, in-process)" python -c "
import json; assert json.load(open('$tmp/p.json'))['proxy_stdio']['added_p95_ms'] < 50"
check "bounded daemon store stays within its cap" python -c "
import json
s = json.load(open('$tmp/p.json'))['daemon_memory']['bounded']['samples']
assert all((x.get('store_size') or 0) <= 200 for x in s), s"
check "latency figure is valid SVG" python -c "
import xml.etree.ElementTree as ET; ET.parse('$tmp/fig/week11-detector-latency.svg')"

echo "== 6. Saved full run =="
saved=docs/results/perf-week11.md
check "$saved exists" test -s "$saved"
check "saved run is the full run (not --quick)" grep -qF -- "- **mode:** full" "$saved"
check "saved run includes 1000-payload stores" grep -qE '^\| 0.9.0 default \| yes \| 1000 \|' "$saved"
check "saved run includes the daemon and memory sections" sh -c \
  "grep -qF '## 3. Daemon over HTTP' '$saved' && grep -qF 'Memory over a long session' '$saved'"
check "docs/results/perf-week11.json parses" python -c "import json; json.load(open('docs/results/perf-week11.json'))"
for fig in week11-detector-latency week11-memory; do
  check "figure $fig.svg is valid SVG" python -c "
import xml.etree.ElementTree as ET; ET.parse('docs/results/figures/$fig.svg')"
done

echo "== 7. Hygiene =="
check "default store bound is 1000 per server" python -c "
from provmcp.config import ProvMcpConfig; assert ProvMcpConfig().proxy.provenance_max_per_server == 1000"
check "detection defaults still frozen at the Week 9 calibration" python -c "
from provmcp.config import DetectionConfig
d = DetectionConfig(); assert d.thresholds == {'substring': 0.428, 'structured': 0.85}"
check "no API key committed to git" sh -c "! git grep -qE 'sk-ant-[A-Za-z0-9_-]{10,}'"

echo "== 8. Git and GitHub =="
branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
check "Week 11 files are committed" \
  git ls-files --error-unmatch docs/week-11.md scripts/verify_week11.sh docs/results/perf-week11.md
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
