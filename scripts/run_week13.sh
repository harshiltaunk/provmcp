#!/usr/bin/env bash
# Week 13 runs (declared scope with real models), one stage at a time.
#
#   bash scripts/run_week13.sh check               free: branch, lint, types, tests, offline evaluation
#   bash scripts/run_week13.sh haiku  [--dry-run]  Claude Haiku 5.5
#   bash scripts/run_week13.sh sonnet [--dry-run]  Claude Sonnet 5.5
#   bash scripts/run_week13.sh opus   [--dry-run]  Claude Opus 5.5
#   bash scripts/run_week13.sh report              docs/results/scope-week13.md from the caches found
#   bash scripts/run_week13.sh status              what has run so far and what it cost
#   bash scripts/run_week13.sh all                 haiku, sonnet, opus, report; stops if a stage looks wrong
#
# A model stage runs the declaration probe first (cheap) and then the
# end-to-end episodes. Every command has a spending cap. Results are cached in
# logs/, so running a stage again resumes it and nothing is paid for twice.
# --dry-run prints the estimates and calls nothing.
#
# The API key is taken from ANTHROPIC_API_KEY, or asked for with hidden input.
# It is never written to a file.
#
# Optional:
#   TRIALS=5 bash scripts/run_week13.sh haiku      more trials of the end-to-end run
#   MAX_USD=30 bash scripts/run_week13.sh sonnet   another cap for the end-to-end run
#                                                  (the cap counts earlier trials too)
set -Eeuo pipefail
cd "$(dirname "$0")/.."
if [ -f .venv/bin/activate ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

STAGE="${1:-}"
DRY=""
if [ "${2:-}" = "--dry-run" ]; then DRY="--dry-run"; fi

EXPECTED_TESTS=334
LOCAL=(-s benchmarks/attacks -s benchmarks/msb -s benchmarks/benign -s benchmarks/inplan -s benchmarks/poisoned)
ALL5="audit,strict,audit-scope,strict-scope,strict-oracle"
IA="benchmarks/external/injecagent"
mkdir -p logs

say() { printf '\n== %s ==\n' "$1"; }
die() { printf '\nSTOPPED: %s\n' "$1" >&2; exit 1; }
trap 'if [ "$BASH_SUBSHELL" -eq 0 ]; then printf "\nSTOPPED: the last command failed (see above). Nothing is lost: the same command resumes.\n" >&2; fi' ERR

usage() {
  sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
}

need_key() {
  if [ -n "$DRY" ]; then return 0; fi
  if [ -z "${ANTHROPIC_API_KEY:-}" ]; then
    read -rs -p "Paste your Anthropic API key (input stays hidden): " ANTHROPIC_API_KEY
    echo
  fi
  if [ -z "${ANTHROPIC_API_KEY:-}" ]; then die "no API key given"; fi
  export ANTHROPIC_API_KEY
}

# On macOS, keep the machine awake while a model stage runs.
stay_awake() {
  if [ -z "$DRY" ] && [ -z "${PROVMCP_AWAKE:-}" ] && command -v caffeinate >/dev/null 2>&1; then
    export PROVMCP_AWAKE=1
    caffeinate -i -w $$ &
  fi
}

# probe <tier> <model> <trials> <injecagent sample> <cap in USD>
probe() {
  local tier="$1" model="$2" trials="$3" limit="$4" cap="$5"
  local paths=("${LOCAL[@]}" -s benchmarks/adaptive)
  if [ -d "$IA" ]; then
    paths+=(-s "$IA")
  else
    echo "note: $IA not found, so InjecAgent is left out of the probe"
  fi
  say "$tier: what scope does it declare? (cap \$$cap)"
  provmcp scope-probe "${paths[@]}" --limit "$limit" --backend anthropic --model "$model" \
    --trials "$trials" --max-usd "$cap" --cache "logs/scope-probe-week13-$tier.jsonl" $DRY \
    2>&1 | tee -a "logs/week13-$tier.log"
}

# run <tier> <model> <conditions> <trials> <cap in USD> <report file> <scenario arguments...>
run() {
  local tier="$1" model="$2" conditions="$3" trials="$4" cap="$5" out="$6"
  shift 6
  say "$tier: end to end, $conditions, $trials trial(s) (cap \$$cap)"
  provmcp agent-run "$@" --conditions "$conditions" --backend anthropic --model "$model" \
    --trials "$trials" --max-usd "$cap" --cache "logs/agent-cache-week13-$tier.jsonl" \
    --workdir "logs/agent-runs-week13-$tier" --out "$out" $DRY \
    2>&1 | tee -a "logs/week13-$tier.log"
}

# status [--gate] [tier...]: counts, tokens and cost from the caches. With --gate
# the exit code is 3 when a tier looks wrong (many errors, or no scope declared).
status() {
  python - "$@" <<'PY'
import json
import sys
from pathlib import Path

from provmcp.agent.experiment import KNOWN_PRICES

gate = "--gate" in sys.argv[1:]
tiers = [a for a in sys.argv[1:] if not a.startswith("--")] or ["haiku", "sonnet", "opus"]


def rows(path):
    file = Path(path)
    if not file.is_file():
        return None
    return [json.loads(line) for line in file.read_text(encoding="utf-8").splitlines() if line.strip()]


def cost(items):
    total = 0.0
    for r in items:
        price_in, price_out = KNOWN_PRICES.get(str(r.get("model", "")).split("@")[0], (0.0, 0.0))
        total += (r.get("input_tokens", 0) * price_in + r.get("output_tokens", 0) * price_out) / 1e6
    return total


grand = 0.0
wrong = []
for tier in tiers:
    found = {
        "probes": rows(f"logs/scope-probe-week13-{tier}.jsonl"),
        "episodes": rows(f"logs/agent-cache-week13-{tier}.jsonl"),
    }
    for label, items in found.items():
        if items is None:
            print(f"{tier:7}{label:9} not run yet")
            continue
        errors = sum(1 for r in items if r.get("error"))
        spent = cost(items)
        grand += spent
        tokens_in = sum(r.get("input_tokens", 0) for r in items)
        tokens_out = sum(r.get("output_tokens", 0) for r in items)
        print(
            f"{tier:7}{label:9} {len(items) - errors} done, {errors} errors, "
            f"{tokens_in:,} in + {tokens_out:,} out tokens, ${spent:.2f}"
        )
        if items and errors / len(items) > 0.10:
            wrong.append(f"{tier} {label}: more than 10% of the calls ended in an error")
    scoped = [
        r for r in found["episodes"] or [] if not r.get("error") and r.get("scope_mode") == "declared"
    ]
    if scoped:
        declared = sum(1 for r in scoped if r.get("declared"))
        print(f"{tier:7}declared a scope in {declared} of {len(scoped)} runs that asked for one")
        if declared / len(scoped) < 0.8:
            wrong.append(f"{tier}: a scope was declared in under 80% of the runs that asked for one")
print(f"total so far: ${grand:.2f}")
for line in wrong:
    print(f"CHECK: {line}")
sys.exit(3 if gate and wrong else 0)
PY
}

capped() {   # capped <tier> <first new line of the log>: say so if a cap ended a run
  local tier="$1" start="$2" hits
  hits=$(tail -n "+$start" "logs/week13-$tier.log" | grep -c "budget of" || true)
  if [ "${hits:-0}" -gt 0 ]; then
    echo
    echo "note: a spending cap ended a run early. The data is usable as it is."
    echo "      To continue it: MAX_USD=<higher cap> bash scripts/run_week13.sh $tier"
  fi
}

model_stage() {
  local tier="$1" start=1
  need_key
  stay_awake
  if [ -f "logs/week13-$tier.log" ]; then
    start=$(( $(wc -l < "logs/week13-$tier.log" | tr -d ' ') + 1 ))
  fi
  case "$tier" in
    haiku)
      probe haiku claude-haiku-5-5 3 200 1
      run haiku claude-haiku-5-5 "$ALL5" "${TRIALS:-3}" "${MAX_USD:-5}" logs/agent-week13-haiku.md "${LOCAL[@]}"
      if [ -d "$IA" ]; then
        run haiku claude-haiku-5-5 audit,strict,strict-scope,strict-oracle 1 2 \
          logs/agent-week13-haiku-injecagent.md -s "$IA" --limit 100
      fi
      ;;
    sonnet)
      probe sonnet claude-sonnet-5-5 1 100 3
      run sonnet claude-sonnet-5-5 "$ALL5" "${TRIALS:-1}" "${MAX_USD:-15}" logs/agent-week13-sonnet.md "${LOCAL[@]}"
      ;;
    opus)
      probe opus claude-opus-5-5 1 100 5
      run opus claude-opus-5-5 audit,strict,strict-scope "${TRIALS:-1}" "${MAX_USD:-15}" \
        logs/agent-week13-opus.md "${LOCAL[@]}"
      ;;
  esac
  if [ -z "$DRY" ]; then
    capped "$tier" "$start"
    say "$tier: summary"
    status "$tier"
  fi
}

check() {
  say "branch"
  local branch
  branch=$(git branch --show-current 2>/dev/null || git rev-parse --abbrev-ref HEAD)
  if [ "$branch" = "main" ]; then die "you are on main. Run: git checkout week-13"; fi
  echo "on $branch"

  say "version"
  local version
  version=$(provmcp version)
  echo "$version"
  case "$version" in
    *0.13.0*) ;;
    *) die 'expected provmcp 0.13.0. Run: pip install -e ".[dev,embed]"' ;;
  esac

  say "lint and types"
  ruff check src tests scripts examples
  ruff format --check src tests scripts examples
  mypy src

  say "tests (one to three minutes)"
  if pytest -q > logs/week13-pytest.log 2>&1; then
    tail -1 logs/week13-pytest.log
  else
    tail -40 logs/week13-pytest.log
    die "tests failed. The full output is in logs/week13-pytest.log"
  fi
  local collected
  collected=$(pytest --collect-only -q 2>/dev/null | grep -Eo '^[0-9]+ tests? collected' | grep -Eo '^[0-9]+' || true)
  if [ "${collected:-0}" != "$EXPECTED_TESTS" ]; then
    die "expected $EXPECTED_TESTS tests, found ${collected:-0}"
  fi
  echo "$collected tests collected"

  # Written to logs/, so a saved report with model results is never overwritten.
  say "offline evaluation (ground-truth scope, no model)"
  python scripts/evaluate_week13.py --out logs/week13-offline.md --json logs/week13-offline.json \
    --figures logs/week13-offline-figures > /dev/null
  grep '^| bundled |' logs/week13-offline.md
  if ! grep -qF "| bundled | scope + provenance (servers and flows) | 14/17 (82%, 59-94) | 0/10 (0%, 0-28) |" \
    logs/week13-offline.md; then
    die "the offline numbers differ from docs/week-13.md"
  fi
  echo
  grep -A 10 '^### InjecAgent, compliant agent' logs/week13-offline.md || true

  say "scripted probe (no model)"
  provmcp scope-probe -s benchmarks/inplan -s benchmarks/poisoned \
    --cache logs/week13-scripted-probe.jsonl > logs/week13-scripted-probe.log 2>&1
  tail -5 logs/week13-scripted-probe.log
  if ! grep -qF "matches ground truth:  23/23 (100%)" logs/week13-scripted-probe.log; then
    die "the scripted probe did not give 23/23"
  fi

  say "check passed"
  echo "Next: bash scripts/run_week13.sh haiku --dry-run"
}

report() {
  local args=() tier
  for tier in haiku sonnet opus; do
    if [ -f "logs/scope-probe-week13-$tier.jsonl" ]; then
      args+=(--probe "$tier=logs/scope-probe-week13-$tier.jsonl")
    fi
    if [ -f "logs/agent-cache-week13-$tier.jsonl" ]; then
      args+=(--run "$tier=logs/agent-cache-week13-$tier.jsonl")
    fi
  done
  say "report"
  python scripts/evaluate_week13.py ${args[@]+"${args[@]}"} > /dev/null
  {
    echo "# Week 13, to send back"
    echo
    echo '```'
    status
    echo '```'
    echo
    cat docs/results/scope-week13.md
  } > logs/week13-send-back.md
  status
  echo
  echo "Report:        docs/results/scope-week13.md"
  echo "Send me this:  logs/week13-send-back.md   (open -R logs/week13-send-back.md shows it in Finder)"
}

case "$STAGE" in
  check) check ;;
  haiku | sonnet | opus) model_stage "$STAGE" ;;
  report) report ;;
  status) status ;;
  all)
    if [ -n "$DRY" ]; then
      for tier in haiku sonnet opus; do model_stage "$tier"; done
      exit 0
    fi
    for tier in haiku sonnet opus; do
      model_stage "$tier"
      if ! status --gate "$tier" > /dev/null; then
        die "$tier looks wrong (see the CHECK line above). Later stages were not started, so nothing more was spent. Send me the summary."
      fi
    done
    report
    ;;
  *)
    usage
    exit 1
    ;;
esac
