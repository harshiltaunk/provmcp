#!/usr/bin/env bash
# Verify Week 12 (adaptive adversary) end to end.
#
#   bash scripts/verify_week12.sh
#
# Re-runs the adaptive evaluation in quick mode (seconds), checks it against
# the expected results, and checks the saved full run. No API calls.
set -u
cd "$(dirname "$0")/.."
[ -f .venv/bin/activate ] && source .venv/bin/activate
export HF_HUB_OFFLINE=1
export LC_ALL=C

VERSION="0.12.0"
EXPECTED_TESTS=266
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

echo "== 2. Week 12 files =="
for f in src/provmcp/adaptive.py src/provmcp/detectors/canonical.py scripts/evaluate_week12.py \
         scripts/generate_adaptive.py docs/week-12.md tests/test_week12_adaptive.py; do
  check "$f" test -s "$f"
done
check "23 adaptive scenarios (18 attacks, 5 benign)" python -c "
from provmcp.benchmark import load_scenarios
s = load_scenarios('benchmarks/adaptive')
assert len(s) == 23 and sum(x.is_attack for x in s) == 18, len(s)"
python scripts/generate_adaptive.py "$tmp/gen" >/dev/null 2>&1
check "generator reproduces the committed scenarios byte for byte" diff -r "$tmp/gen" benchmarks/adaptive

echo "== 3. Code quality =="
check "ruff check"          ruff check src tests scripts examples
check "ruff format --check" ruff format --check src tests scripts examples
check "mypy src (strict)"   mypy src

echo "== 4. Tests =="
collected=$(pytest --collect-only -q 2>/dev/null | grep -Eo '^[0-9]+ tests? collected' | grep -Eo '^[0-9]+')
check "pytest collects $EXPECTED_TESTS tests (found ${collected:-0})" test "${collected:-0}" = "$EXPECTED_TESTS"
pytest -q -rs >"$tmp/pytest.txt" 2>&1; rc=$?
check "pytest: no failures ($(tail -1 "$tmp/pytest.txt"))" test "$rc" = 0

echo "== 5. Adaptive evaluation reproduces (quick, no embedding) =="
python scripts/evaluate_week12.py --quick --skip-embedding --injecagent "$tmp/none" \
  --out "$tmp/a.md" --json "$tmp/a.json" --figures "$tmp/fig" >/dev/null 2>&1
check "default: 1/17 evasions flagged, 0/17 caught, 0/5 false alarms" grep -qF \
  "| 0.9.0 default | 1/17 (6%, 1-27) | 0/17 (0%, 0-18) | 0/5 (0%, 0-43) |" "$tmp/a.md"
check "canonical: 11/17 flagged, 10/17 caught, 0/5 false alarms" grep -qF \
  "| default + canonical | 11/17 (65%, 41-83) | 10/17 (59%, 36-78) | 0/5 (0%, 0-43) |" "$tmp/a.md"
check "canonical on the corpus: 14/17 attacks, same 3/10 false alarms" grep -qF \
  "| default + canonical | 14/17 (82%, 59-94) | 3/10 (30%, 11-60) |" "$tmp/a.md"
check "self-flushing evades exactly at the cap" grep -qF \
  "| 0.9.0 default | caught | caught | caught | **missed** | **missed** |" "$tmp/a.md"
check "adaptive figure is valid SVG" python -c "
import xml.etree.ElementTree as ET; ET.parse('$tmp/fig/week12-adaptive.svg')"

echo "== 6. Saved full run =="
saved=docs/results/adaptive-week12.md
check "$saved exists" test -s "$saved"
check "saved run is the full run (not --quick)" grep -qF -- "- **mode:** full" "$saved"
check "saved run used the real cap of 1000" grep -qF "(cap 1000 per server)" "$saved"
check "saved adaptive totals match a fresh run (non-embedding strategies)" python -c "
def rows(path):
    text = open(path).read()
    section = text[text.index('| strategy | evasions flagged'):text.index('![Adaptive')]
    return [l for l in section.splitlines() if l.startswith('| ') and 'embedding' not in l]
fresh, saved = rows('$tmp/a.md'), rows('$saved')
assert len(fresh) == 3 and fresh == saved, (fresh, saved)"
check "saved run includes InjecAgent" sh -c "! grep -qF 'Not run: \`benchmarks/external/injecagent\`' '$saved'"
if [ -f "$HAIKU10" ]; then
  check "saved run replays the Week 10 Haiku traffic" grep -qF "**haiku-week10**" "$saved"
else
  skp "Week 10 Haiku cache not found ($HAIKU10)"
fi
check "docs/results/adaptive-week12.json parses" python -c "import json; json.load(open('docs/results/adaptive-week12.json'))"
check "figure week12-adaptive.svg is valid SVG" python -c "
import xml.etree.ElementTree as ET; ET.parse('docs/results/figures/week12-adaptive.svg')"

echo "== 7. Hygiene =="
check "detection defaults frozen; canonical views opt-in" python -c "
from provmcp.config import DetectionConfig
d = DetectionConfig()
assert d.thresholds == {'substring': 0.428, 'structured': 0.85} and not d.canonicalize"
check "no API key committed to git" sh -c "! git grep -qE 'sk-ant-[A-Za-z0-9_-]{10,}'"

echo "== 8. Git and GitHub =="
branch=$(git rev-parse --abbrev-ref HEAD 2>/dev/null)
check "Week 12 files are committed" \
  git ls-files --error-unmatch docs/week-12.md scripts/verify_week12.sh docs/results/adaptive-week12.md
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
