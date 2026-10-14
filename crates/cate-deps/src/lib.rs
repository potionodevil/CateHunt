// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! cate-deps: Lockfile-Parser (cargo/package-lock) + Registry-Check Stub
//! (Slopsquatting: Existenz/Alter/Downloads).
use cate_core::EvidenceLevel;
use serde::{Deserialize, Serialize};

/// Eine Abhaengigkeit aus einem Lockfile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub version: String,
    pub registry: String,
    pub evidence: EvidenceLevel,
}

/// Ergebnis des Registry-Checks (Stub).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryCheck {
    pub name: String,
    pub version: String,
    pub exists: bool,
    pub age_days: Option<u64>,
    pub downloads: Option<u64>,
    pub slopsquat_suspicious: bool,
    pub evidence: EvidenceLevel,
}

/// Parst `Cargo.lock` (TOML-minimal): sucht `[[package]]`-Bloecke mit
/// name/version/source. Reicht als Phase-1-Stub ohne TOML-Crate.
pub fn parse_cargo_lock(content: &str) -> Vec<Dependency> {
    let mut out = Vec::new();
    let mut name = String::new();
    let mut version = String::new();
    let mut source = String::new();
    let mut in_pkg = false;
    let flush = |name: &mut String,
                 version: &mut String,
                 source: &mut String,
                 out: &mut Vec<Dependency>| {
        if !name.is_empty() {
            out.push(Dependency {
                name: std::mem::take(name),
                version: std::mem::take(version),
                registry: if source.is_empty() {
                    "local".to_string()
                } else {
                    std::mem::take(source)
                },
                evidence: EvidenceLevel::E0,
            });
        } else {
            name.clear();
            version.clear();
            source.clear();
        }
    };
    for line in content.lines() {
        let t = line.trim();
        if t == "[[package]]" {
            if in_pkg {
                flush(&mut name, &mut version, &mut source, &mut out);
            }
            in_pkg = true;
            continue;
        }
        if !in_pkg {
            continue;
        }
        if let Some(v) = kv_value(t, "name") {
            name = v;
        } else if let Some(v) = kv_value(t, "version") {
            version = v;
        } else if let Some(v) = kv_value(t, "source") {
            source = v;
        }
    }
    if in_pkg {
        flush(&mut name, &mut version, &mut source, &mut out);
    }
    out
}

fn kv_value(line: &str, key: &str) -> Option<String> {
    let rest = line
        .strip_prefix(key)?
        .trim_start()
        .strip_prefix('=')?
        .trim();
    let v = rest.trim_matches('"').to_string();
    Some(v)
}

/// Parst `package-lock.json` (npm v7+): `packages[""].dependencies` wird
/// ignoriert, stattdessen `dependencies`-Map (v1) oder
/// `packages`-Map (v2/v3) mit node_modules/-Praefix.
pub fn parse_package_lock(json: &str) -> Result<Vec<Dependency>, String> {
    let v: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("package-lock parse: {e}"))?;
    let mut out = Vec::new();
    if let Some(deps) = v.get("dependencies").and_then(|d| d.as_object()) {
        for (name, info) in deps {
            let version = info
                .get("version")
                .and_then(|x| x.as_str())
                .unwrap_or("?")
                .to_string();
            out.push(Dependency {
                name: name.clone(),
                version,
                registry: "npm".to_string(),
                evidence: EvidenceLevel::E0,
            });
        }
    }
    if let Some(pkgs) = v.get("packages").and_then(|p| p.as_object()) {
        for (path, info) in pkgs {
            if path.is_empty() {
                continue;
            }
            let name = path
                .strip_prefix("node_modules/")
                .unwrap_or(path)
                .to_string();
            if name.is_empty() || name.contains("node_modules/") {
                continue; // nur Top-Level
            }
            if out.iter().any(|d: &Dependency| d.name == name) {
                continue;
            }
            let version = info
                .get("version")
                .and_then(|x| x.as_str())
                .unwrap_or("?")
                .to_string();
            out.push(Dependency {
                name,
                version,
                registry: "npm".to_string(),
                evidence: EvidenceLevel::E0,
            });
        }
    }
    Ok(out)
}

/// Registry-Check Stub (kein Netzwerk in Phase 1):
/// Heuristik: Name mit Tippfehler-Muster (z.B. Dopplung, bekannte Praefixe)
/// oder Version "0.0.0" gilt als verdaechtig. Echte Pruefung
/// (Existenz/Alter/Downloads via crates.io-/npm-API) folgt in Phase 2.
pub fn registry_check_stub(dep: &Dependency) -> RegistryCheck {
    registry_check_offline(dep, None)
}

/// Offline-Eintrag der Registry-Datenbank (naechste Stufe, kein Netz):
/// Existenz, Alter in Tagen und Downloadzahl aus einer lokalen DB
/// (z.B. eingecheckter Snapshot). Ohne DB gilt altes Stub-Verhalten.
#[derive(Debug, Clone)]
pub struct OfflineEntry {
    pub exists: bool,
    pub age_days: Option<u64>,
    pub downloads: Option<u64>,
}

/// Offline-Registry-Datenbank: (name, registry) -> Eintrag.
/// Befuellung aus Snapshot-Datei/Seed; kein Netzwerkzugriff.
#[derive(Debug, Clone, Default)]
pub struct OfflineDb {
    entries: std::collections::HashMap<(String, String), OfflineEntry>,
}

impl OfflineDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, name: &str, registry: &str, entry: OfflineEntry) {
        self.entries
            .insert((name.to_string(), registry.to_string()), entry);
    }

    pub fn get(&self, name: &str, registry: &str) -> Option<&OfflineEntry> {
        self.entries.get(&(name.to_string(), registry.to_string()))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Registry-Check gegen Offline-DB (kein Netz):
/// - Treffer: exists/age_days/downloads aus der DB; verdaechtig nur bei
///   heuristischem Typosquat-Muster oder fehlender Existenz.
/// - Fehltritt (mit DB): exists=false, keine Alter/Downloads, verdaechtig.
/// - Ohne DB (None): altes Stub-Verhalten (exists=true, keine Felder).
pub fn registry_check_offline(dep: &Dependency, db: Option<&OfflineDb>) -> RegistryCheck {
    let heuristic = dep.version == "0.0.0"
        || dep.name.contains("--")
        || dep.name.len() == 1
        || looks_like_typosquat(&dep.name);
    match db {
        None => RegistryCheck {
            name: dep.name.clone(),
            version: dep.version.clone(),
            exists: true, // Stub: keine Netzpruefung
            age_days: None,
            downloads: None,
            slopsquat_suspicious: heuristic,
            evidence: EvidenceLevel::E0,
        },
        Some(db) => match db.get(&dep.name, &dep.registry) {
            Some(e) => RegistryCheck {
                name: dep.name.clone(),
                version: dep.version.clone(),
                exists: e.exists,
                age_days: e.age_days,
                downloads: e.downloads,
                slopsquat_suspicious: heuristic || !e.exists,
                evidence: EvidenceLevel::E0,
            },
            None => RegistryCheck {
                name: dep.name.clone(),
                version: dep.version.clone(),
                exists: false,
                age_days: None,
                downloads: None,
                slopsquat_suspicious: true, // unbekannt = verdaechtig
                evidence: EvidenceLevel::E0,
            },
        },
    }
}

fn looks_like_typosquat(name: &str) -> bool {
    // Sehr grobe Heuristik: haeufige Zielpakete mit 1-Zeichen-Abweichung.
    const POPULAR: &[&str] = &["lodash", "axios", "serde", "tokio", "react", "express"];
    let n = name.to_lowercase();
    POPULAR.iter().any(|p| edit_distance_one(&n, p))
}

fn edit_distance_one(a: &str, b: &str) -> bool {
    if a == b {
        return false;
    }
    let (ac, bc): (Vec<char>, Vec<char>) = (a.chars().collect(), b.chars().collect());
    if ac.len() == bc.len() {
        ac.iter().zip(bc.iter()).filter(|(x, y)| x != y).count() == 1
    } else if ac.len() + 1 == bc.len() || bc.len() + 1 == ac.len() {
        let (short, long) = if ac.len() < bc.len() {
            (ac, bc)
        } else {
            (bc, ac)
        };
        let mut i = 0;
        let mut j = 0;
        let mut skipped = false;
        while i < short.len() && j < long.len() {
            if short[i] == long[j] {
                i += 1;
                j += 1;
            } else if !skipped {
                skipped = true;
                j += 1;
            } else {
                return false;
            }
        }
        true
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cargo_lock_parses() {
        let lock = "[[package]]\nname = \"serde\"\nversion = \"1.0.0\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\n";
        let d = parse_cargo_lock(lock);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].name, "serde");
    }

    #[test]
    fn typosquat_stub_flags() {
        let dep = Dependency {
            name: "lodas".to_string(),
            version: "1.0.0".to_string(),
            registry: "npm".to_string(),
            evidence: EvidenceLevel::E0,
        };
        assert!(registry_check_stub(&dep).slopsquat_suspicious);
    }

    #[test]
    fn offline_db_hit_fills_fields() {
        let dep = Dependency {
            name: "serde".to_string(),
            version: "1.0.0".to_string(),
            registry: "crates.io".to_string(),
            evidence: EvidenceLevel::E0,
        };
        let mut db = OfflineDb::new();
        db.insert(
            "serde",
            "crates.io",
            OfflineEntry {
                exists: true,
                age_days: Some(900),
                downloads: Some(50_000_000),
            },
        );
        let c = registry_check_offline(&dep, Some(&db));
        assert!(c.exists);
        assert_eq!(c.age_days, Some(900));
        assert_eq!(c.downloads, Some(50_000_000));
        assert!(!c.slopsquat_suspicious);
    }

    #[test]
    fn offline_db_miss_means_not_exists_and_suspicious() {
        let dep = Dependency {
            name: "völlig-unbekannt-xyz".to_string(),
            version: "0.0.1".to_string(),
            registry: "crates.io".to_string(),
            evidence: EvidenceLevel::E0,
        };
        let db = OfflineDb::new();
        let c = registry_check_offline(&dep, Some(&db));
        assert!(!c.exists);
        assert_eq!(c.age_days, None);
        assert_eq!(c.downloads, None);
        assert!(c.slopsquat_suspicious);
    }

    #[test]
    fn stub_without_db_keeps_old_behavior() {
        let dep = Dependency {
            name: "serde".to_string(),
            version: "1.0.0".to_string(),
            registry: "crates.io".to_string(),
            evidence: EvidenceLevel::E0,
        };
        let c = registry_check_stub(&dep);
        assert!(c.exists);
        assert!(!c.slopsquat_suspicious);
    }
}
