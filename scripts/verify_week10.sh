#!/usr/bin/env bash
# Verify Week 10 (full evaluation) end to end.
#
#   bash scripts/verify_week10.sh
#
# No API calls. Checks the evaluation reproduces, the saved report and
# figures exist and parse, and the cache keys separate detector settings.
set -u
cd "$(dirname "$0")/.."
[ -f .venv/bin/activate ] && source .venv/bin/activate
export HF_HUB_OFFLINE=1
export LC_ALL=C

VERSION="0.10.0"
EXPECTED_TESTS=216
HAIKU10="logs/agent-cache-haiku-week10.jsonl"

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

echo "== 2. Week 10 files =="
for f in src/provmcp/evaluation.py src/provmcp/svgchart.py scripts/evaluate_week10.py \
         docs/week-10.md tests/test_week10_evaluation.py; do
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

echo "== 5. Evaluation reproduces (corpus level) =="
python scripts/evaluate_week10.py --skip-embedding --injecagent "$tmp/none" \
  --out "$tmp/e.md" --json "$tmp/e.json" --figures "$tmp/fig" >/dev/null 2>&1
check "default: 12/17 attacks, 3/10 false alarms, 7/8 held-out" grep -qF \
  "| 0.9.0 default (substring + structured) | 12/17 (71%, 47-87) | 3/10 (30%, 11-60) | 7/8 (88%, 53-98) |" "$tmp/e.md"
check "Week 7 settings: 8/17 attacks" grep -qF \
  "| Week 7 settings | 8/17 (47%, 26-69) | 3/10 (30%, 11-60) |" "$tmp/e.md"
check "corpus figure is valid SVG" python -c "
import xml.etree.ElementTree as ET; ET.parse('$tmp/fig/week10-corpus.svg')"

echo "== 6. Saved results =="
saved=docs/results/eval-week10.md
check "$saved exists" test -s "$saved"
check "saved corpus rows match a fresh run (non-embedding strategies)" python -c "
def rows(path):
    text = open(path).read()
    section = text[text.index('## 1. Corpus'):text.index('![Corpus')]
    return [l for l in section.splitlines() if l.startswith('| ') and 'embedding' not in l]
fresh, saved = rows('$tmp/e.md'), rows('$saved')
assert len(fresh) == 5 and fresh == saved, (fresh, saved)"
check "docs/results/eval-week10.json parses" python -c "import json; json.load(open('docs/results/eval-week10.json'))"
for fig in week10-corpus week10-injecagent; do
  if [ -f "docs/results/figures/$fig.svg" ]; then
    check "figure $fig.svg is valid SVG" python -c "
import xml.etree.ElementTree as ET; ET.parse('docs/results/figures/$fig.svg')"
  else
    bad "docs/results/figures/$fig.svg missing"
  fi
done
if [ -f "$HAIKU10" ]; then
  check "report includes the Week 10 Haiku runs" grep -qF "### haiku-week10" "$saved"
  check "Week 10 Haiku runs used the 0.9.0 settings" python -c "
import json
labels = {json.loads(l).get('detection', '') for l in open('$HAIKU10') if l.strip()}
assert any('metadata:on' in x for x in labels), labels"
  check "Week 10 Haiku baseline report saved" test -s docs/results/baseline-week10-haiku.md
else
  skp "Week 10 Haiku cache not found ($HAIKU10)"
fi

echo "== 7. Cache safety and hygiene =="
check "cache keys include the detector settings" python -c "
from provmcp.agent.experiment import episode_key
assert episode_key('s', 'strict', 'm', 0, 'a') != episode_key('s', 'strict', 'm', 0, 'b')"
check "no API key committed to git" sh -c "! git grep -qE 'sk-ant-[A-Za-z0-9_-]{10,}'"
check "defaults still the Week 9 calibration (frozen)" python -c "
from provmcp.config import DetectionConfig
d = DetectionConfig()
assert d.thresholds == {'substring': 0.428, 'structured': 0.85} and d.track_tool_metadata"

echo "== 8. Git and GitHub =="
branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
check "Week 10 files are committed" \
  git ls-files --error-unmatch docs/week-10.md scripts/verify_week10.sh docs/results/eval-week10.md
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
