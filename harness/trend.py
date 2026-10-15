#!/usr/bin/env python3
# Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
# oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
"""Trend-Report pro Modell/Engine (M-5).

Liest Verdict-Cache-JSONL (s. `cate-triage` CacheRecord: Top-Level
`fingerprint` + geflatteter Verdict ODER `{"verdict": {...}}`-Schachtelung)
und optional Fix-Audit-Logs, gruppiert pro Modell/Engine:

  Anzahl, confirm (open), suppress (close), escalate (demote),
  Deny-Hochstufungen (`policy_override == true`, d.h. Policy hat ein
  Close auf Deny-CWE zu Demote korrigiert).

Ausgabe: ASCII-Tabelle + JSON (`--format table|json|both`), optional
JSON-Export via `--json-out`. Reiner Report, kein Gate (Exit 0 bei
valider Eingabe).

Beispiel:
  python harness/trend.py --verdicts harness/tests/fixtures/trend_verdicts.jsonl
  python harness/trend.py --verdicts v.jsonl --audit a.jsonl --format json
"""
import argparse
import json
import os
import sys

ALIASES = {
    "open": "confirm", "confirm": "confirm",
    "close": "suppress", "suppress": "suppress",
    "demote": "escalate", "escalate": "escalate",
}


def norm_action(raw):
    """Verdict-Vokabular (Rust-Cache, Paket-A, Harness) -> confirm/suppress/escalate."""
    a = str(raw or "open").strip().lower()
    return ALIASES.get(a, "other")


def as_verdict(obj):
    """Toleriert geflattete CacheRecords und {"verdict": {...}}-Schachtelung."""
    if isinstance(obj.get("verdict"), dict):
        v = dict(obj["verdict"])
        v.setdefault("model", obj.get("model", obj.get("engine", "")))
        v.setdefault("cwe", obj.get("cwe", ""))
        v.setdefault("policy_override", obj.get("policy_override", False))
        return v
    return obj


def model_of(v):
    for key in ("model", "engine"):
        m = str(v.get(key, "") or "").strip()
        if m:
            return m
    return "unknown"


def load_verdicts(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for lineno, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(as_verdict(json.loads(line)))
            except json.JSONDecodeError as e:
                raise ValueError(f"{path}:{lineno}: ungültiges JSON ({e})")
    return rows


def load_audit(path):
    """Audit als JSON-Array ODER JSONL (Fix-Audit: proposal_id/event/actor)."""
    with open(path, encoding="utf-8") as f:
        text = f.read().strip()
    if not text:
        return []
    if text.startswith("["):
        data = json.loads(text)
        return data if isinstance(data, list) else [data]
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def summarize(rows):
    per_model = {}
    for v in rows:
        m = model_of(v)
        s = per_model.setdefault(m, {"total": 0, "confirm": 0, "suppress": 0,
                                     "escalate": 0, "other": 0, "deny_upgrades": 0})
        s["total"] += 1
        s[norm_action(v.get("action", v.get("verdict", "open")))] += 1
        if v.get("policy_override") is True:
            s["deny_upgrades"] += 1
    total = {"total": 0, "confirm": 0, "suppress": 0,
             "escalate": 0, "other": 0, "deny_upgrades": 0}
    for s in per_model.values():
        for k in total:
            total[k] += s[k]
    return {"models": per_model, "total": total}


def summarize_audit(entries):
    by_actor, applied = {}, 0
    for e in entries:
        if not isinstance(e, dict):
            continue
        if str(e.get("event", "")).strip().lower() == "applied":
            applied += 1
            actor = str(e.get("actor", "unknown") or "unknown")
            by_actor[actor] = by_actor.get(actor, 0) + 1
    return {"entries": len(entries), "applied": applied, "applied_by_actor": by_actor}


def fmt_table(report):
    models = report["models"]
    width = max([len("Modell")] + [len(m) for m in models] + [6])
    head = (f"{'Modell':<{width}}  Anzahl  Confirm  Suppress  Escalate  Deny-Upgr.")
    lines = [head, "-" * len(head)]
    for m in sorted(models):
        s = models[m]
        lines.append(f"{m:<{width}}  {s['total']:>6}  {s['confirm']:>7}  "
                     f"{s['suppress']:>8}  {s['escalate']:>8}  {s['deny_upgrades']:>10}")
    t = report["total"]
    lines.append("-" * len(head))
    lines.append(f"{'GESAMT':<{width}}  {t['total']:>6}  {t['confirm']:>7}  "
                 f"{t['suppress']:>8}  {t['escalate']:>8}  {t['deny_upgrades']:>10}")
    if report.get("audit"):
        a = report["audit"]
        lines.append(f"Audit: {a['entries']} Einträge, {a['applied']} applied "
                     f"({', '.join(f'{k}={v}' for k, v in sorted(a['applied_by_actor'].items()))})")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Trend-Report pro Modell/Engine (M-5).")
    ap.add_argument("--verdicts", required=True, help="Verdict-Cache-JSONL")
    ap.add_argument("--audit", default=None, help="Audit-Log (JSON-Array oder JSONL, optional)")
    ap.add_argument("--format", choices=("table", "json", "both"), default="both")
    ap.add_argument("--json-out", default=None, help="JSON-Report zusätzlich in Datei schreiben")
    args = ap.parse_args()

    for p in [args.verdicts] + ([args.audit] if args.audit else []):
        if not os.path.exists(p):
            ap.error(f"Datei nicht gefunden: {p}")

    report = summarize(load_verdicts(args.verdicts))
    report["source"] = {"verdicts": args.verdicts, "audit": args.audit}
    if args.audit:
        report["audit"] = summarize_audit(load_audit(args.audit))

    if args.format in ("table", "both"):
        print(fmt_table(report))
    if args.format in ("json", "both"):
        if args.format == "both":
            print()
        print(json.dumps(report, indent=2, sort_keys=True))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, sort_keys=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
