# IntentBench-Lite Traces Directory

This directory contains the **200 step-labeled JSONL trace files** comprising the **IntentBench-Lite** benchmark dataset.

For complete research-grade documentation detailing the JSONL schema, scenario taxonomy, feature telemetry, ground-truth annotations, and how this dataset is used to train and calibrate the CTAG detection model, read:

👉 **[DATASET_SPECIFICATION.md](file:///c:/Users/Parv%20Saini/Desktop/intentguard-mvp/traces/DATASET_SPECIFICATION.md)**

---

## Quick Summary

- **Total Traces:** 200 JSONL files
- **Malicious Traces (`label = 1`):** 80 files (40%)
- **Benign Plain Traces (`label = 0`):** 60 files (30%)
- **Benign Similar Confounder Traces (`label = 0`):** 60 files (30%)

To regenerate or customize dataset size:
```bash
python generate_dataset.py --num-traces 200 --out-dir traces --seed 42
```
