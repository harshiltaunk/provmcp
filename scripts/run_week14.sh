#!/usr/bin/env bash
# Week 14 runs (real models and the evasions, the scope ablation, more trials).
#
#   bash scripts/run_week14.sh check               free: branch, lint, types, tests, offline evaluation
#   bash scripts/run_week14.sh haiku  [--dry-run]  Claude Haiku 5.5
#   bash scripts/run_week14.sh sonnet [--dry-run]  Claude Sonnet 5.5
#   bash scripts/run_week14.sh opus   [--dry-run]  Claude Opus 5.5
#   bash scripts/run_week14.sh report              docs/results/realworld-week14.md from the caches found
#   bash scripts/run_week14.sh status              what has run so far and what it cost
#   bash scripts/run_week14.sh all                 haiku, sonnet, opus, report; stops if a stage looks wrong
#
# A model stage runs three things, cheapest first: the evasion scenarios, the
# ablation arms on the poisoned catalogs, and the Week 13 conditions with three
# trials. The last one starts from a copy of the Week 13 cache, so episodes
# already paid for are reused and the Week 13 files are never touched. Every
# command has a spending cap. Results are cached in logs/, so running a stage
# again resumes it. --dry-run prints the estimates and calls nothing.
#
# The API key is taken from ANTHROPIC_API_KEY, or asked for with hidden input.
# It is never written to a file.
#
# Optional:
#   TRIALS=5 bash scripts/run_week14.sh haiku      more trials everywhere
#   MAX_USD=30 bash scripts/run_week14.sh opus     another cap for the more-trials run
#                                                  (the cap counts reused episodes too)
set -Eeuo pipefail
cd "$(dirname "$0")/.."
if [ -f .venv/bin/activate ]; then
  # shellcheck disable=SC1091
  source .venv/bin/activate
fi

STAGE="${1:-}"
DRY=""
if [ "${2:-}" = "--dry-run" ]; then DRY="--dry-run"; fi

EXPECTED_TESTS=357
LOCAL=(-s benchmarks/attacks -s benchmarks/msb -s benchmarks/benign -s benchmarks/inplan -s benchmarks/poisoned)
ALL5="audit,strict,audit-scope,strict-scope,strict-oracle"
EVASION="audit,strict,strict-canonical,strict-scope"
ABLATION="audit,audit-warn,audit-scope-plain,audit-scope"
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

# run <tier> <model> <cache> <conditions> <trials> <cap> <report file> <scenario arguments...>
run() {
  local tier="$1" model="$2" cache="$3" conditions="$4" trials="$5" cap="$6" out="$7"
  shift 7
  say "$tier: $conditions, $trials trial(s) (cap \$$cap)"
  provmcp agent-run "$@" --conditions "$conditions" --backend anthropic --model "$model" \
    --trials "$trials" --max-usd "$cap" --cache "$cache" \
    --workdir "logs/agent-runs-week14-$tier" --out "$out" $DRY \
    2>&1 | tee -a "logs/week14-$tier.log"
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
        "new": rows(f"logs/agent-cache-week14-{tier}.jsonl"),
        "trials": rows(f"logs/agent-cache-week14-trials-{tier}.jsonl"),
    }
    # The more-trials cache starts as a copy of Week 13's: count only what was added.
    paid_before = rows(f"logs/agent-cache-week13-{tier}.jsonl") or []
    if found["trials"] is not None:
        found["trials"] = found["trials"][len(paid_before) :]
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
            f"{tier:7}{label:9} {len(items) - errors} new, {errors} errors, "
            f"{tokens_in:,} in + {tokens_out:,} out tokens, ${spent:.2f}"
        )
        if items and errors / len(items) > 0.10:
            wrong.append(f"{tier} {label}: more than 10% of the calls ended in an error")
    scoped = [
        r
        for r in (found["new"] or []) + (found["trials"] or [])
        if not r.get("error") and r.get("scope_mode") == "declared"
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
  hits=$(tail -n "+$start" "logs/week14-$tier.log" | grep -c "budget of" || true)
  if [ "${hits:-0}" -gt 0 ]; then
    echo
    echo "note: a spending cap ended a run early. The data is usable as it is."
    echo "      To continue it: MAX_USD=<higher cap> bash scripts/run_week14.sh $tier"
  fi
}

model_stage() {
  local tier="$1" model cap_evasion cap_ablation cap_trials start=1
  local new="logs/agent-cache-week14-$tier.jsonl"
  local trials_cache="logs/agent-cache-week14-trials-$tier.jsonl"
  local trials="${TRIALS:-3}"
  case "$tier" in
    haiku)  model=claude-haiku-5-5;  cap_evasion=1; cap_ablation=1; cap_trials="${MAX_USD:-3}" ;;
    sonnet) model=claude-sonnet-5-5; cap_evasion=5; cap_ablation=3; cap_trials="${MAX_USD:-10}" ;;
    opus)   model=claude-opus-5-5;   cap_evasion=8; cap_ablation=5; cap_trials="${MAX_USD:-16}" ;;
  esac
  need_key
  stay_awake
  if [ -f "logs/week14-$tier.log" ]; then
    start=$(( $(wc -l < "logs/week14-$tier.log" | tr -d ' ') + 1 ))
  fi
  # Start the more-trials cache from Week 13's, once. The Week 13 file is only read.
  if [ -z "$DRY" ] && [ ! -f "$trials_cache" ] && [ -f "logs/agent-cache-week13-$tier.jsonl" ]; then
    cp "logs/agent-cache-week13-$tier.jsonl" "$trials_cache"
    echo "started $trials_cache from the Week 13 cache"
  fi
  run "$tier" "$model" "$new" "$EVASION" "$trials" "$cap_evasion" \
    "logs/agent-week14-$tier-evasion.md" -s benchmarks/realworld
  run "$tier" "$model" "$new" "$ABLATION" "$trials" "$cap_ablation" \
    "logs/agent-week14-$tier-ablation.md" -s benchmarks/poisoned
  run "$tier" "$model" "$trials_cache" "$ALL5" "$trials" "$cap_trials" \
    "logs/agent-week14-$tier-trials.md" "${LOCAL[@]}"
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
  if [ "$branch" = "main" ]; then die "you are on main. Run: git checkout week-14"; fi
  echo "on $branch"

  say "version"
  local version
  version=$(provmcp version)
  echo "$version"
  case "$version" in
    *0.14.0*) ;;
    *) die 'expected provmcp 0.14.0. Run: pip install -e ".[dev,embed]"' ;;
  esac

  say "lint and types"
  ruff check src tests scripts examples
  ruff format --check src tests scripts examples
  mypy src

  say "tests (one to three minutes)"
  if pytest -q > logs/week14-pytest.log 2>&1; then
    tail -1 logs/week14-pytest.log
  else
    tail -40 logs/week14-pytest.log
    die "tests failed. The full output is in logs/week14-pytest.log"
  fi
  local collected
  collected=$(pytest --collect-only -q 2>/dev/null | grep -Eo '^[0-9]+ tests? collected' | grep -Eo '^[0-9]+' || true)
  if [ "${collected:-0}" != "$EXPECTED_TESTS" ]; then
    die "expected $EXPECTED_TESTS tests, found ${collected:-0}"
  fi
  echo "$collected tests collected"

  say "offline evaluation (compliant agent, no model)"
  python scripts/evaluate_week14.py --out logs/week14-offline.md --json logs/week14-offline.json \
    --figures logs/week14-offline-figures > /dev/null
  grep -F '**total**' logs/week14-offline.md
  if ! grep -qF "| **total** |  | 2/16 | 10/16 | 8/16 |" logs/week14-offline.md; then
    die "the offline numbers differ from docs/week-14.md"
  fi

  say "scripted agent on the new scenarios (no model)"
  rm -f logs/week14-scripted.jsonl
  provmcp agent-run -s benchmarks/realworld --conditions "$EVASION" \
    --cache logs/week14-scripted.jsonl --workdir logs/agent-runs-week14-scripted \
    --out logs/week14-scripted.md > logs/week14-scripted.log 2>&1
  tail -1 logs/week14-scripted.log
  if ! grep -qF "76 episode(s) reported" logs/week14-scripted.log; then
    die "the scripted run did not report 76 episodes"
  fi

  say "check passed"
  echo "Next: bash scripts/run_week14.sh haiku --dry-run"
}

report() {
  local args=() tier
  for tier in haiku sonnet opus; do
    if [ -f "logs/agent-cache-week14-$tier.jsonl" ]; then
      args+=(--run "$tier=logs/agent-cache-week14-$tier.jsonl")
    fi
    if [ -f "logs/agent-cache-week14-trials-$tier.jsonl" ]; then
      args+=(--trials "$tier=logs/agent-cache-week14-trials-$tier.jsonl")
    fi
  done
  say "report"
  python scripts/evaluate_week14.py ${args[@]+"${args[@]}"} > /dev/null
  {
    echo "# Week 14, to send back"
    echo
    echo '```'
    status
    echo '```'
    echo
    cat docs/results/realworld-week14.md
  } > logs/week14-send-back.md
  status
  echo
  echo "Report:        docs/results/realworld-week14.md"
  echo "Send me this:  logs/week14-send-back.md   (open -R logs/week14-send-back.md shows it in Finder)"
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
