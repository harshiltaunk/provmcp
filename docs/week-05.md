# Week 5 log — Sep 21 to 25

## Done

- `provmcp/detectors/base.py` — `Detector` Protocol every detector satisfies.
- `provmcp/detectors/embedding.py` — `EmbeddingDetector` using
  `sentence-transformers/all-MiniLM-L6-v2` on CPU. Lazy-loads torch;
  degrades to an empty-findings no-op with a one-line warning when
  sentence-transformers is not installed.
- `provmcp/detectors/composite.py` — `CompositeDetector` runs several
  detectors and merges per `(source, target)` pair, keeping the
  highest-confidence finding and joining detector names with `+`.
- Benchmark runner now accepts any `Detector`, not just substring.
- `provmcp run-benchmark` gained `--detector substring|embedding|composite`
  and `--embedding-threshold` options.
- Second attack scenario: `cd_002_paraphrased_calendar_to_email.json`.
  The substring detector misses it on purpose so the embedding detector
  has a real target.
- `scripts/sweep_embedding_threshold.py` scans thresholds from 0.45 to
  0.95 in steps of 0.025 and prints TP/FP/TN/FN plus precision and recall.

## Test counts

- **68 tests, all passing** (was 59 at end of Week 4). Embedding tests
  use an injected stub model so the suite does not require
  sentence-transformers or torch to be installed.

## Try it

```bash
# install the optional embedding extra (~200 MB; pulls torch)
pip install -e ".[embed]"

# run each detector against the growing corpus
provmcp run-benchmark --scenarios benchmarks/attacks --detector substring
provmcp run-benchmark --scenarios benchmarks/attacks --detector embedding
provmcp run-benchmark --scenarios benchmarks/attacks --detector composite

# sweep the embedding threshold to find the operating point
python scripts/sweep_embedding_threshold.py
```

Expected: substring catches `cd-001` (direct marker) but misses `cd-002`.
Embedding catches both (near-paraphrase). Composite catches both and
labels the agreement as `embedding+substring` on `cd-001`.

## Not done yet

- Only one benign scenario exists. The false-positive story needs
  several more benign traces before the threshold sweep is informative.
- No structured-field detector. That is Week 6.

## Next up (Week 6)

- `provmcp/detectors/structured.py` — typed-field reuse (emails, URLs,
  file paths, order IDs) that neither substring nor embedding reliably
  catches when the value is short.
- Three more benign scenarios so the false-positive baseline is real.
- First cross-dataset confusion-matrix snapshot combining all three
  detectors at the sweep-picked threshold.
