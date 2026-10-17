// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! SARIF-Negativfaelle (P2, TESTING.md §1.1/§4.1): kaputte, leere und
//! locations-lose SARIFs duerfen nie panicken — sauberer Fehler ODER
//! `unlocated=true` (fliesst nicht in Health ein).

use cate_sarif::import_sarif;

#[test]
fn kaputtes_json_gibt_sauberen_fehler() {
    let err = import_sarif("{kein json").unwrap_err();
    assert!(err.contains("sarif parse"), "Fehlertext: {err}");
}

#[test]
fn leeres_dokument_gibt_sauberen_fehler() {
    for doc in ["", "   ", "null", "[]", "{}"] {
        assert!(
            import_sarif(doc).is_err(),
            "erwartet Err fuer {doc:?}, kein Panic/Ok"
        );
    }
}

#[test]
fn runs_leer_liefert_leere_liste() {
    let f = import_sarif(r#"{"version":"2.1.0","runs":[]}"#).unwrap();
    assert!(f.is_empty());
}

#[test]
fn run_ohne_results_liefert_leere_liste() {
    let f = import_sarif(r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}}}]"#)
        .unwrap_or_default();
    assert!(f.is_empty());
}

#[test]
fn fehlende_locations_werden_unlocated() {
    // Kein `locations`-Schluessel ueberhaupt (serde-Default greift).
    let json = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},
      "results":[{"ruleId":"r","message":{"text":"x"}}]}]}"#;
    let f = import_sarif(json).unwrap();
    assert_eq!(f.len(), 1);
    assert!(f[0].unlocated);
    assert_eq!(f[0].path, "");
    assert_eq!(f[0].start_line, 0);
}

#[test]
fn locations_null_gibt_sauberen_fehler_statt_panic() {
    // `null` ist kein Array — serde-Fehler, aber kein Panic.
    let json = r#"{"version":"2.1.0","runs":[
      {"results":[{"ruleId":"r","locations":null}]}]}"#;
    let err = import_sarif(json).unwrap_err();
    assert!(err.contains("sarif parse"), "Fehlertext: {err}");
}

#[test]
fn physical_location_ohne_uri_wird_unlocated() {
    let json = r#"{"version":"2.1.0","runs":[{"results":[
      {"ruleId":"r","message":{"text":"x"},
       "locations":[{"physicalLocation":{"region":{"startLine":5}}}]}]}]}"#;
    let f = import_sarif(json).unwrap();
    assert_eq!(f.len(), 1);
    assert!(f[0].unlocated, "uri fehlt -> unverwertbar");
}

#[test]
fn fehlende_rule_id_wird_unknown_nicht_fehler() {
    let json = r#"{"version":"2.1.0","runs":[{"results":[
      {"message":{"text":"x"},
       "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{}}}]}]}]}"#;
    let f = import_sarif(json).unwrap();
    assert_eq!(f[0].rule_id, "unknown");
    assert!(!f[0].unlocated);
}

#[test]
fn unlocated_zaehlt_nicht_als_lokalisierter_fund() {
    // Gemischter Run: 1 lokalisiert + 2 unlocated.
    let json = r#"{"version":"2.1.0","runs":[{"results":[
      {"ruleId":"a","message":{"text":"x"},
       "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{"startLine":1}}}]},
      {"ruleId":"b","message":{"text":"y"},"locations":[]},
      {"ruleId":"c","message":{"text":"z"}}
    ]}]}"#;
    let f = import_sarif(json).unwrap();
    assert_eq!(f.len(), 3);
    let located = f.iter().filter(|x| !x.unlocated).count();
    assert_eq!(
        located, 1,
        "nur lokalisierte Funde duerfen in Health einfließen"
    );
}
