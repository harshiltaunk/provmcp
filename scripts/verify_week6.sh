#!/usr/bin/env bash
# Verify Week 6 is complete. Run from anywhere: bash scripts/verify_week6.sh
set -u
cd "$(dirname "$0")/.."
[ -f .venv/bin/activate ] && source .venv/bin/activate
export HF_HUB_OFFLINE=1

pass=0; fail=0; skip=0
ok()   { echo "  PASS  $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $1"; fail=$((fail+1)); }
skp()  { echo "  SKIP  $1"; skip=$((skip+1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }

echo "== Git =="
git fetch -q origin 2>/dev/null
check "on branch main"                    test "$(git branch --show-current)" = main
check "working tree clean"                test -z "$(git status --porcelain)"
check "local main matches GitHub"         test "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)"
check "Week 6 commit merged to main"      bash -c "git log origin/main --oneline | grep -q 'Week 6'"

echo "== Version =="
check "provmcp version is 0.6.0"          test "$(python -c 'import provmcp;print(provmcp.__version__)')" = 0.6.0

echo "== Files =="
for f in src/provmcp/detectors/structured.py \
         benchmarks/attacks/cd_003_recased_address_exfiltration.json \
         benchmarks/benign/bn_002_readme_then_clock.json \
         benchmarks/benign/bn_003_convert_meeting_time.json \
         benchmarks/benign/bn_004_reply_to_organizer.json \
         scripts/evaluate_corpus.py tests/test_structured_detector.py docs/week-06.md \
         docs/results/README.md docs/results/eval-week6-t072.md \
         docs/results/eval-week6-t052.md docs/results/sweep-week6.txt; do
  check "exists: $f" test -f "$f"
done
check "3 attack scenarios"                test "$(ls benchmarks/attacks/*.json | wc -l | tr -d ' ')" = 3
check "4 benign scenarios"                test "$(ls benchmarks/benign/*.json | wc -l | tr -d ' ')" = 4

echo "== Quality =="
out=$(pytest -q 2>&1 | tail -1)
if [[ "$out" == *"87 passed"* && "$out" != *failed* && "$out" != *error* ]]; then ok "pytest: 87 passed"; else bad "pytest: got '$out'"; fi
check "ruff check clean"                  ruff check src tests scripts
check "ruff format clean"                 ruff format --check src tests scripts
check "mypy clean"                        mypy src

echo "== Behaviour =="
check "CLI structured: TP=2 FP=0 TN=0 FN=1 on attacks" \
  bash -c "provmcp run-benchmark --scenarios benchmarks/attacks --detector structured 2>/dev/null | grep -q 'TP=2 FP=0 TN=0 FN=1'"
eval072=$(python scripts/evaluate_corpus.py --embedding-threshold 0.72 2>/dev/null)
check "substring row  1/1/3/2"            grep -qF "| substring | 1 | 1 | 3 | 2 |" <<<"$eval072"
check "structured row 2/1/3/1"            grep -qF "| structured | 2 | 1 | 3 | 1 |" <<<"$eval072"
check "bn-004 flagged (known limitation)" bash -c "grep -F 'bn-004' <<<\"\$0\" | grep -q flag" "$eval072"

if python -c "import sentence_transformers" >/dev/null 2>&1; then
  eval052=$(python scripts/evaluate_corpus.py --embedding-threshold 0.52 2>/dev/null)
  check "embedding@0.52 row 3/0/4/0"      grep -qF "| embedding | 3 | 0 | 4 | 0 |" <<<"$eval052"
  check "composite@0.52 row 3/1/3/0"      grep -qF "| composite | 3 | 1 | 3 | 0 |" <<<"$eval052"
  check "cd-002 caught only by embedding" bash -c "grep -F 'cd-002' <<<\"\$0\" | grep -q '| - | - | flag | flag |'" "$eval052"
else
  skp "embedding checks (sentence-transformers not installed)"
fi

echo "== GitHub =="
remote=$(gh api repos/harshiltaunk/provmcp/contents/docs/results --jq '.[].name' 2>/dev/null | sort | tr '\n' ' ')
expected="README.md eval-week6-t052.md eval-week6-t072.md sweep-week5.txt sweep-week6.txt "
if [ "$remote" = "$expected" ]; then ok "docs/results on GitHub (5 files)"; else bad "docs/results on GitHub: got '$remote'"; fi

echo
echo "Week 6: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
