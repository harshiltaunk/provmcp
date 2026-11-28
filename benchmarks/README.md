# Benchmarks

One JSON file per scenario. `provmcp.benchmark.load_scenarios(folder)` reads a
folder. Values are synthetic; the generated families use `.example` domains.

| folder | ids | count | what |
|---|---|---|---|
| `attacks/` | `cd-*` | 13 | cross-server confused-deputy attacks |
| `msb/` | `msb-*` | 4 | attacks derived from MCPSecBench attack types |
| `benign/` | `bn-*` | 10 | benign multi-server tasks, the false-alarm corpus |
| `adaptive/` | `ad-*`, `bn-ad-*` | 18 + 5 | Week 12 evasions and their benign counterparts |
| `inplan/` | `ip-*`, `bn-ip-*` | 4 + 4 | Week 13 attacks that stay inside the declared plan, and benign twins with the same request |
| `poisoned/` | `dp-*`, `bn-dp-*` | 12 + 3 | Week 13 tool descriptions that ask to be declared, and controls with a neutral description |
| `realworld/` | `rw-*`, `bn-rw-*` | 16 + 3 | Week 14 tasks for a live agent: 8 evasion techniques in a delegated and an injected framing, and benign counterparts |
| `splits/` | | | the frozen Week 6 corpus and the Week 9 calibration split |
| `external/` | `ia-*` | | InjecAgent cases from `scripts/import_injecagent.py` (generated, not committed) |

`adaptive/` is written by `scripts/generate_adaptive.py`, and `inplan/` and
`poisoned/` by `scripts/generate_scope_scenarios.py`, and `realworld/` by
`scripts/generate_week14.py`. Change the generator,
not the files. Tests check that each generator reproduces the committed files
byte for byte.

## Scenario fields

| field | meaning |
|---|---|
| `id`, `title`, `description` | identity |
| `task` | the user's request, given to an agent |
| `scope` | ground truth for declared scope (Week 13): `servers` the request needs and `flows` as `[source, target]` pairs, written from the task text alone |
| `servers[]` | `id`, `display_name`, `trust`, and `canned`: the `tools/list` result and a `responses` map from tool name to result (a list is a sequence of results) |
| `trace[]` | the calls a compliant agent makes; `expect_cross_origin_from` marks a step that should be flagged; `session` starts a fresh provenance store (Week 12) |
| `oracle` | for agent runs: `entry` is the call that exposes the agent to the scenario's content, `goal` the calls that must reach their server (for an attack, the attacker's objective) |
| `ground_truth` | `cross_server_influence` for an attack |
| `metadata` | source, `task_type` (`fully-specified`, `param-open`, `action-open`), technique, and for `poisoned/` the `hostile_server` |

A minimal example is `inplan/ip_01_extra_recipient.json`.
