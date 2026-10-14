#!/usr/bin/env python3
"""CateHunt Benchmark-Harness Stub (Phase 2).

Vermisst Triage-Entscheidungen gegen Benchmark-Labels und weist
FP-Reduktion UND echte-Funde-Unterdrueckung getrennt aus.
Suppression Rate > 1% => FAILED (HARD GATE), unabhaengig von FP-Reduktion.

Naechste Schritte: Anbindung OWASP Benchmark expectedresults-*.csv
und SastBench-Splits (s. docs/VALIDATION.md 1.1-1.2).

Gebrauch:
  python harness.py --verdicts results/verdicts.jsonl --labels tests/fixtures/labels.csv
"""
import argparse, csv, json, sys


def load_verdicts(path):
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            v = json.loads(line)
            out[v["fingerprint"]] = v.get("action", "open")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verdicts", required=True)
    ap.add_argument("--labels", required=True)
    args = ap.parse_args()

    verdicts = load_verdicts(args.verdicts)
    tp_total = fp_total = 0
    suppressed_real = 0
    reduced_fp = 0
    with open(args.labels, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            fp_id, label = row["fingerprint"], row["label"].strip().lower()
            action = verdicts.get(fp_id, "open")
            closed = action == "close"
            if label == "vulnerable":
                tp_total += 1
                if closed:
                    suppressed_real += 1
            elif label == "fixed":
                fp_total += 1
                if closed:
                    reduced_fp += 1

    supp = (suppressed_real / tp_total) if tp_total else 0.0
    fpr = (reduced_fp / fp_total) if fp_total else 0.0
    summary = {
        "tp_total": tp_total,
        "fp_total": fp_total,
        "suppressed_real": suppressed_real,
        "reduced_fp": reduced_fp,
        "suppression_rate": round(supp, 4),
        "fp_reduction": round(fpr, 4),
        "gate": "FAILED" if supp > 0.01 else "PASSED",
    }
    print(json.dumps(summary, indent=2))
    return 1 if summary["gate"] == "FAILED" else 0


if __name__ == "__main__":
    sys.exit(main())
