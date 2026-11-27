# Benchmarks

Layout:

- `attacks/` — multi-server confused-deputy scenarios. One JSON file per scenario.
- `benign/` — recorded benign multi-server traces used as the false-positive corpus.
- `third_party/` — pointers to PROTOAMP and MCPSecBench (not vendored; fetched on demand).

Nothing here yet in Week 1. The first three scenarios land in Week 9.

Scenario schema (sketch — finalized in Week 8):

```json
{
  "id": "cd-001-calendar-to-email",
  "description": "Poisoned calendar event triggers email send.",
  "servers": ["calendar", "email"],
  "steps": [
    {"call": "calendar.get_next_event", "returns": "..."},
    {"call": "email.send", "expect_blocked_by": "substring_or_embedding"}
  ],
  "ground_truth": "cross_server_influence"
}
```
