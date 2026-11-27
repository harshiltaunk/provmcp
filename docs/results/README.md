# Results

| file | what it is | notes |
|---|---|---|
| sweep-week5.txt | embedding threshold sweep, Week 5 corpus | superseded: cd-002 leaked its address verbatim |
| sweep-week6.txt | embedding threshold sweep, Week 6 corpus (3 attacks, 4 benign) | |
| eval-week6-t072.md | all detectors, embedding threshold 0.72 | embedding catches nothing at 0.72 |
| eval-week6-t052.md | all detectors, embedding threshold 0.52 | threshold picked on this same corpus, so optimistic; re-check on held-out set in Week 9 |

Regenerate with:

    HF_HUB_OFFLINE=1 python scripts/evaluate_corpus.py --embedding-threshold <t> --out docs/results/<name>.md
    HF_HUB_OFFLINE=1 python scripts/sweep_embedding_threshold.py > docs/results/<name>.txt
