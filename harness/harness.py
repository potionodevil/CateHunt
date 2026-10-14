#!/usr/bin/env python3
# Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
# oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
"""CateHunt Benchmark-Harness (Phase 2 + Paket C).

Vermisst Triage-Entscheidungen gegen Benchmark-Labels und weist
FP-Reduktion UND echte-Funde-Unterdrueckung getrennt aus.
Suppression Rate > 1% => FAILED (HARD GATE), unabhaengig von FP-Reduktion.

Modi:
  Fixture-Modus (Demo/CI-Negativcheck):
    python harness.py --verdicts results/verdicts.jsonl --labels tests/fixtures/labels.csv
  Korpus-Modus (Paket C, simulierte Triage ueber vuln/fixed-Paare):
    python harness.py --corpus ../corpus/manifest.json

Korpus-Regel: Deny-Faelle (deny=true) werden NIE geschlossen
(vuln -> open, fixed -> open, konservativ). Nicht-Deny: vuln -> open,
fixed -> close. Gate FAILED bei Suppression >1% (s. docs/VALIDATION.md 1.3).
"""
import argparse
import csv
import hashlib
import json
import os
import sys

SUPPRESSION_GATE = 0.01


def norm_action(v):
    """Toleriert Gross/Klein + Verdict-Aliase (Rust-Cache, Paket-A-Vokabular)."""
    a = str(v.get("action", v.get("verdict", "open"))).strip().lower()
    if a == "suppress":
        return "close"
    if a == "escalate":
        return "demote"
    if a == "confirm":
        return "open"
    return a


def load_verdicts(path):
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            v = json.loads(line)
            out[v["fingerprint"]] = norm_action(v)
    return out


def summarize(pairs):
    """pairs: [(fingerprint, label, action, cwe)] -> Kennzahlen-Dict."""
    tp_total = fp_total = 0
    suppressed_real = 0
    reduced_fp = 0
    per_cwe_real = {}
    per_cwe_supp = {}
    for fp, label, action, cwe in pairs:
        closed = action == "close"
        if label == "vulnerable":
            tp_total += 1
            per_cwe_real[cwe] = per_cwe_real.get(cwe, 0) + 1
            if closed:
                suppressed_real += 1
                per_cwe_supp[cwe] = per_cwe_supp.get(cwe, 0) + 1
        elif label == "fixed":
            fp_total += 1
            if closed:
                reduced_fp += 1
    supp = (suppressed_real / tp_total) if tp_total else 0.0
    fpr = (reduced_fp / fp_total) if fp_total else 0.0
    per_cwe = {
        cwe: round(per_cwe_supp.get(cwe, 0) / n, 4) for cwe, n in per_cwe_real.items()
    }
    return {
        "tp_total": tp_total,
        "fp_total": fp_total,
        "suppressed_real": suppressed_real,
        "reduced_fp": reduced_fp,
        "suppression_rate": round(supp, 4),
        "fp_reduction": round(fpr, 4),
        "suppression_per_cwe": per_cwe,
        "gate": "FAILED" if supp > SUPPRESSION_GATE else "PASSED",
    }


def corpus_fingerprint(case_id, path):
    with open(path, "rb") as f:
        digest = hashlib.sha256(case_id.encode() + b"\x00" + f.read()).hexdigest()[:16]
    return digest


def resolve_case_file(base, ref):
    """Manifest-Pfade sind repo-relativ (corpus/...) — von Manifest-dir
    oder Repo-Root aufloesen."""
    cands = [
        os.path.normpath(os.path.join(base, ref)),
        os.path.normpath(os.path.join(os.path.dirname(base), ref)),
    ]
    for cand in cands:
        if os.path.exists(cand):
            return cand
    return cands[0]


def run_corpus(manifest_path):
    """Simulierte Triage ueber Korpus-Paare, Deny-Faelle nie close."""
    with open(manifest_path, encoding="utf-8") as f:
        manifest = json.load(f)
    base = os.path.dirname(os.path.abspath(manifest_path))
    pairs = []
    cases = []
    for case in manifest["cases"]:
        cid, cwe, deny = case["id"], case["cwe"], bool(case.get("deny", False))
        vuln_p = resolve_case_file(base, case["vulnerable"])
        fixed_p = resolve_case_file(base, case["fixed"])
        fp_v = corpus_fingerprint(cid + ":vuln", vuln_p)
        fp_f = corpus_fingerprint(cid + ":fixed", fixed_p)
        if deny:
            av, af = "open", "open"  # Deny: nie schliessen, Fix konservativ offen
        else:
            av, af = "open", "close"
        pairs.append((fp_v, "vulnerable", av, cwe))
        pairs.append((fp_f, "fixed", af, cwe))
        cases.append({"id": cid, "cwe": cwe, "deny": deny,
                      "vuln_fp": fp_v, "fixed_fp": fp_f,
                      "vuln_action": av, "fixed_action": af})
    summary = summarize(pairs)
    summary["cases"] = len(cases)
    summary["case_detail"] = cases
    deny_closed = [c["id"] for c in cases if c["deny"] and
                   (c["vuln_action"] == "close" or c["fixed_action"] == "close")]
    summary["deny_closed"] = deny_closed
    if deny_closed:
        summary["gate"] = "FAILED"
    return summary


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verdicts", default=None)
    ap.add_argument("--labels", default=None)
    ap.add_argument("--corpus", default=None,
                    help="Pfad zu corpus/manifest.json (Korpus-Modus)")
    args = ap.parse_args()

    if args.corpus:
        if args.verdicts or args.labels:
            ap.error("--corpus schliesst --verdicts/--labels aus")
        summary = run_corpus(args.corpus)
        print(json.dumps(summary, indent=2))
        return 1 if summary["gate"] == "FAILED" else 0

    if not args.verdicts or not args.labels:
        ap.error("Fixture-Modus braucht --verdicts UND --labels (oder --corpus)")

    verdicts = load_verdicts(args.verdicts)
    pairs = []
    with open(args.labels, encoding="utf-8") as f:
        for row in csv.DictReader(f):
            fp_id, label = row["fingerprint"], row["label"].strip().lower()
            action = verdicts.get(fp_id, "open")
            pairs.append((fp_id, label, action, row.get("notes", "")))
    summary = summarize(pairs)
    print(json.dumps(summary, indent=2))
    return 1 if summary["gate"] == "FAILED" else 0


if __name__ == "__main__":
    sys.exit(main())
