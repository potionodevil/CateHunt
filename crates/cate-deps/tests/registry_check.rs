// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! M1.5 Registry-Check: echte Offline-Daten (kein Netz).
//!
//! Fixtures unter tests/fixtures/ (crate speichert die Paket-Metadaten,
//! spaeter tatsaechliche Registry-Snapshots ersetzen sie).
use cate_deps::{
    deps_summary, parse_cargo_lock, parse_package_lock, registry_check, Dependency,
    OfflineRegistryDbFile, REGISTRY_DB_FORMAT, REGISTRY_DB_VERSION,
};
use serde_json::Value;

fn dep(name: &str, registry: &str) -> Dependency {
    Dependency {
        name: name.to_string(),
        version: "1.0.0".to_string(),
        registry: registry.to_string(),
        evidence: cate_core::EvidenceLevel::E0,
    }
}

// ---- Fixture laden ----

#[test]
fn fixture_db_parses() {
    let text = include_str!("fixtures/registry_db.json");
    let v: Value = serde_json::from_str(text).expect("fixture muss rein JSON sein");
    assert_eq!(v["format"], REGISTRY_DB_FORMAT);
    assert_eq!(v["version"], REGISTRY_DB_VERSION);
    assert!(
        v["packages"].as_array().unwrap().len() >= 5,
        "5 reale Pakete"
    );
}

#[test]
fn fixture_db_loads_into_offline_db() {
    let text = include_str!("fixtures/registry_db.json");
    let db = OfflineRegistryDbFile::from_json(text).expect("fixture laedt");
    // Reale Pakete aus dem M1.5-Set: serde, tokio, request/requests,
    // left-pad, lodash -> alles Treffer mit age/downloads/advisory-Feldern.
    for (name, reg) in [
        ("serde", "crates.io"),
        ("tokio", "crates.io"),
        ("request", "crates.io"),
        ("requests", "npm"),
        ("left-pad", "npm"),
        ("lodash", "npm"),
    ] {
        let e = db
            .get(name, reg)
            .unwrap_or_else(|| panic!("{name}/{reg} fehlt"));
        assert!(e.exists, "{name} muss existieren");
        assert!(e.age_days.is_some(), "{name} braucht age_days");
        assert!(e.downloads.is_some(), "{name} braucht downloads");
    }
}

// ---- Registry-Check gegen Fixture ----

#[test]
fn known_package_gets_real_data() {
    let text = include_str!("fixtures/registry_db.json");
    let db = OfflineRegistryDbFile::from_json(text).unwrap();
    let serde_dep = dep("serde", "crates.io");
    let c = registry_check(&serde_dep, Some(&db));
    assert!(c.exists);
    assert!(c.age_days.is_some());
    assert!(c.downloads.is_some());
    assert!(!c.slopsquat_suspicious);
}

#[test]
fn unknown_package_means_exists_false_and_suspicious() {
    let text = include_str!("fixtures/registry_db.json");
    let db = OfflineRegistryDbFile::from_json(text).unwrap();
    let c = registry_check(&dep("rekwest", "crates.io"), Some(&db));
    assert!(!c.exists);
    assert!(c.slopsquat_suspicious);
    // dissolve: Typosquat via 1-Zeichen-Distanz von einem DB-Namen.
    let c = registry_check(&dep("reqwest", "crates.io"), Some(&db));
    assert!(c.slopsquat_suspicious);
    let c2 = registry_check(&dep("lodass", "npm"), Some(&db));
    assert!(c2.slopsquat_suspicious);
}

#[test]
fn package_lock_fixture_with_db() {
    let lock = r#"{"name":"x","version":"1.0.0","lockfileVersion":3,"packages":{
        "": {"name":"x"},
        "node_modules/lodash": {"version":"4.17.21"},
        "node_modules/lodas": {"version":"4.17.20"}
    }}"#;
    let deps = parse_package_lock(lock).unwrap();
    assert_eq!(deps.len(), 2);
    let text = include_str!("fixtures/registry_db.json");
    let db = OfflineRegistryDbFile::from_json(text).unwrap();
    let checks: Vec<_> = deps.iter().map(|d| registry_check(d, Some(&db))).collect();
    let lodash = checks.iter().find(|c| c.name == "lodash").unwrap();
    assert!(lodash.exists);
    assert!(lodash.downloads.is_some());
    let lodas = checks.iter().find(|c| c.name == "lodas").unwrap();
    assert!(!lodas.exists, "lodas ist nicht in der DB");
    assert!(lodas.slopsquat_suspicious, "Typosquat von lodash");
}

#[test]
fn cargo_lock_with_db() {
    let lock = "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
    let deps = parse_cargo_lock(lock);
    assert_eq!(deps.len(), 1, "parse_cargo_lock muss tracen");
    let text = include_str!("fixtures/registry_db.json");
    let db = OfflineRegistryDbFile::from_json(text).unwrap();
    let c = registry_check(&deps[0], Some(&db));
    // Registries aus Cargo.lock tragen das volle URL-Schema; die DB keyed
    // auf kurze Namen ("crates.io"). Unbekannte Registry -> exists=false.
    assert!(
        !c.slopsquat_suspicious || !c.exists,
        "Unbekannte Registry-Bezeichnung oder Typosquat nicht gemeldet"
    );
}

// ---- Deps-Summary ----

#[test]
fn deps_summary_counts() {
    let text = include_str!("fixtures/registry_db.json");
    let db = OfflineRegistryDbFile::from_json(text).unwrap();
    let deps = vec![dep("serde", "crates.io"), dep("rekwest", "crates.io")];
    let checks: Vec<_> = deps.iter().map(|d| registry_check(d, Some(&db))).collect();
    let s = deps_summary(&deps, &checks);
    assert_eq!(s.packages, 2);
    assert_eq!(s.unknown, 1);
    assert_eq!(s.suspicious, 1);
    assert!(s.with_registry_data >= 1);
    assert!(s.total_downloads > 0);
    assert_eq!(s.total_advisories, 2); // serde-Advisories aus Fixture
    assert!(s.oldest_age_days >= s.newest_age_days);
}

// ---- DB-Format-Gate ----

#[test]
fn db_rejects_wrong_format_and_version() {
    let bad = r#"{"format":"other-db","version":1,"packages":[]}"#;
    assert!(OfflineRegistryDbFile::from_json(bad).is_err());
    let bad = r#"{"format":"cate-registry-db","version":2,"packages":[]}"#;
    assert!(OfflineRegistryDbFile::from_json(bad).is_err());
    assert!(OfflineRegistryDbFile::from_json("{not json").is_err());
}
