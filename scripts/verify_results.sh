#!/usr/bin/env bash
# Verify that every result in docs/results is:
#   1. saved locally and non-empty
#   2. well-formed (expected tables, headers, row counts)
#   3. committed to git and identical to origin/main
#   4. on GitHub, byte-identical to the local copy
#   5. reproducible: rerunning the current code gives the same output
#
# Usage: bash scripts/verify_results.sh
set -u
cd "$(dirname "$0")/.."
[ -f .venv/bin/activate ] && source .venv/bin/activate
export HF_HUB_OFFLINE=1
export LC_ALL=C

REPO="harshiltaunk/provmcp"
DIR="docs/results"
FILES="README.md eval-week6-t052.md eval-week6-t072.md sweep-week5.txt sweep-week6.txt"

pass=0; fail=0; skip=0
ok()    { echo "  PASS  $1"; pass=$((pass+1)); }
bad()   { echo "  FAIL  $1"; fail=$((fail+1)); }
skp()   { echo "  SKIP  $1"; skip=$((skip+1)); }
check() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then ok "$d"; else bad "$d"; fi; }

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "== 1. Saved locally =="
for f in $FILES; do
  check "$f exists and is non-empty" test -s "$DIR/$f"
done

echo "== 2. Contents look right =="
check "t072: has score table"               grep -qF "| detector | TP | FP | TN | FN |" "$DIR/eval-week6-t072.md"
check "t072: header says threshold 0.720"   grep -qF "embedding threshold 0.720" "$DIR/eval-week6-t072.md"
check "t052: header says threshold 0.520"   grep -qF "embedding threshold 0.520" "$DIR/eval-week6-t052.md"
check "t052: lists all 7 scenarios" \
  test "$(grep -cE '^\| (cd|bn)-' "$DIR/eval-week6-t052.md")" = 7
check "sweep-week6: 3 attacks, 4 benign"    grep -qF "Loaded 3 attack scenario(s) and 4 benign scenario(s)" "$DIR/sweep-week6.txt"
check "sweep-week6: 21 threshold rows" \
  test "$(grep -cE '^ +0\.[0-9]{3} ' "$DIR/sweep-week6.txt")" = 21
for f in $FILES; do
  [ "$f" = README.md ] && continue
  check "README indexes $f" grep -qF "$f" "$DIR/README.md"
done

echo "== 3. Committed to git =="
git fetch -q origin 2>/dev/null
for f in $FILES; do
  check "$f tracked by git" git ls-files --error-unmatch "$DIR/$f"
done
check "no uncommitted changes in $DIR"     test -z "$(git status --porcelain -- "$DIR")"
check "$DIR identical to origin/main"      git diff --quiet origin/main -- "$DIR"

echo "== 4. On GitHub, byte-identical =="
remote=$(gh api "repos/$REPO/contents/$DIR" --jq '.[] | "\(.name) \(.sha)"' 2>/dev/null)
if [ -z "$remote" ]; then
  bad "could not list $DIR on GitHub (run: gh auth status)"
else
  for f in $FILES; do
    rsha=$(awk -v n="$f" '$1==n {print $2}' <<<"$remote")
    lsha=$(git hash-object "$DIR/$f" 2>/dev/null)
    if [ -z "$rsha" ]; then
      bad "$f missing on GitHub"
    elif [ "$rsha" = "$lsha" ]; then
      ok "$f on GitHub matches local"
    else
      bad "$f on GitHub differs from local"
    fi
  done
fi

echo "== 5. Reproducible from current code =="
python scripts/evaluate_corpus.py --split benchmarks/splits/week6.json --embedding-threshold 0.72 --out "$tmp/t072.md" >/dev/null 2>&1
check "eval-week6-t072.md reproduces exactly" diff -q "$tmp/t072.md" "$DIR/eval-week6-t072.md"
if python -c "import sentence_transformers" >/dev/null 2>&1; then
  python scripts/evaluate_corpus.py --split benchmarks/splits/week6.json --embedding-threshold 0.52 --out "$tmp/t052.md" >/dev/null 2>&1
  check "eval-week6-t052.md reproduces exactly" diff -q "$tmp/t052.md" "$DIR/eval-week6-t052.md"
  python scripts/sweep_embedding_threshold.py --split benchmarks/splits/week6.json 2>/dev/null >"$tmp/sweep.txt"
  check "sweep-week6.txt reproduces exactly"    diff -q "$tmp/sweep.txt" "$DIR/sweep-week6.txt"
else
  skp "embedding reruns (sentence-transformers not installed)"
fi
echo "  note  sweep-week5.txt is a historical record of the old corpus and is not rerun"

echo
echo "Results: $pass passed, $fail failed, $skip skipped"
[ "$fail" -eq 0 ]
