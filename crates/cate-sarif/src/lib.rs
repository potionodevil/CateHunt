// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! cate-sarif: SARIF Minimal-Import (Evidence E1).
use cate_core::EvidenceLevel;
use serde::{Deserialize, Serialize};

/// Minimaler SARIF-Finding-Import. Alles aus SARIF startet als E1
/// (Tool-Behauptung, nicht verifiziert).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SarifFinding {
    pub rule_id: String,
    pub message: String,
    pub path: String,
    pub start_line: usize,
    pub level: String,
    pub evidence: EvidenceLevel,
    /// true, wenn keine verwertbare `locations[].physicalLocation`
    /// vorhanden ist (PLAN.md meet 173): fliesst NICHT in Health ein.
    #[serde(default)]
    pub unlocated: bool,
    /// Tool-Herkunft aus `tool.driver.name`: `semgrep` | `codeql` | `sarif`.
    #[serde(default)]
    pub provenance: String,
    /// kanonisch `CWE-<digits>`, Default `CWE-000` (kein Treffer).
    #[serde(default)]
    pub cwe: String,
}

#[derive(Debug, Deserialize)]
struct SarifLog {
    runs: Vec<SarifRun>,
}

#[derive(Debug, Deserialize)]
struct SarifRun {
    #[serde(default)]
    tool: SarifTool,
    #[serde(default)]
    results: Vec<SarifResult>,
}

#[derive(Debug, Default, Deserialize)]
struct SarifTool {
    #[serde(default)]
    driver: SarifDriver,
}

#[derive(Debug, Default, Deserialize)]
struct SarifDriver {
    #[serde(default)]
    name: String,
    #[serde(default)]
    rules: Vec<SarifRule>,
}

#[derive(Debug, Default, Deserialize)]
struct SarifRule {
    #[serde(default)]
    id: String,
    #[serde(default)]
    properties: SarifRuleProps,
}

#[derive(Debug, Default, Deserialize)]
struct SarifRuleProps {
    #[serde(default)]
    cwe: Option<serde_json::Value>,
    #[serde(default)]
    tags: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SarifResult {
    #[serde(rename = "ruleId", default)]
    rule_id: String,
    #[serde(default)]
    message: SarifMessage,
    #[serde(default)]
    level: Option<String>,
    #[serde(default)]
    locations: Vec<SarifLocation>,
}

#[derive(Debug, Default, Deserialize)]
struct SarifMessage {
    #[serde(default)]
    text: String,
}

#[derive(Debug, Deserialize)]
struct SarifLocation {
    #[serde(rename = "physicalLocation", default)]
    physical_location: SarifPhysical,
}

#[derive(Debug, Default, Deserialize)]
struct SarifPhysical {
    #[serde(rename = "artifactLocation", default)]
    artifact_location: SarifArtifact,
    #[serde(default)]
    region: SarifRegion,
}

#[derive(Debug, Default, Deserialize)]
struct SarifArtifact {
    #[serde(default)]
    uri: String,
}

#[derive(Debug, Default, Deserialize)]
struct SarifRegion {
    #[serde(rename = "startLine", default)]
    start_line: usize,
}

/// Importiert SARIF-JSON (String) -> Findings mit Evidence E1.
/// Unbekannte/fehlende Felder bekommen Defaults, kein harter Abbruch.
/// Ohne verwertbare `locations[].physicalLocation` (leeres Array oder
/// leere `artifactLocation.uri`) wird `unlocated=true` gesetzt.
pub fn import_sarif(json: &str) -> Result<Vec<SarifFinding>, String> {
    let log: SarifLog = serde_json::from_str(json).map_err(|e| format!("sarif parse: {e}"))?;
    let mut out = Vec::new();
    for run in &log.runs {
        let provenance = provenance_of(&run.tool.driver.name);
        // Regel-Metadaten: id -> CWE (CodeQL-Tags `external/cwe/cwe-XXX`,
        // Semgrep-`properties.cwe`, jeweils tolerant geparst).
        let mut rule_cwe: std::collections::HashMap<&str, String> =
            std::collections::HashMap::new();
        for rule in &run.tool.driver.rules {
            let cwe = rule
                .properties
                .cwe
                .as_ref()
                .and_then(value_cwe)
                .or_else(|| rule.properties.tags.iter().find_map(|t| extract_cwe(t)));
            if let Some(c) = cwe {
                rule_cwe.insert(rule.id.as_str(), c);
            }
        }
        for r in &run.results {
            let loc = r
                .locations
                .first()
                .filter(|l| !l.physical_location.artifact_location.uri.trim().is_empty());
            let (path, line, unlocated) = match loc {
                Some(l) => (
                    l.physical_location.artifact_location.uri.clone(),
                    l.physical_location.region.start_line,
                    false,
                ),
                None => (String::new(), 0, true),
            };
            let rule_id = if r.rule_id.is_empty() {
                "unknown".to_string()
            } else {
                r.rule_id.clone()
            };
            let cwe = rule_cwe
                .get(rule_id.as_str())
                .cloned()
                .or_else(|| extract_cwe(&rule_id))
                .or_else(|| extract_cwe(&r.message.text))
                .unwrap_or_else(|| "CWE-000".to_string());
            out.push(SarifFinding {
                message: r.message.text.clone(),
                path,
                start_line: line,
                level: r.level.clone().unwrap_or_else(|| "warning".to_string()),
                evidence: EvidenceLevel::E1,
                unlocated,
                provenance: provenance.clone(),
                cwe,
                rule_id,
            });
        }
    }
    Ok(out)
}

/// `tool.driver.name` -> Provenienz-Tag (CodeQL vs. Semgrep, sonst `sarif`).
fn provenance_of(driver_name: &str) -> String {
    let n = driver_name.to_ascii_lowercase();
    if n.contains("codeql") {
        "codeql".to_string()
    } else if n.contains("semgrep") {
        "semgrep".to_string()
    } else {
        "sarif".to_string()
    }
}

/// Sucht `CWE-<digits>` (tolerant: `CWE328`, `CWE 328`, Pfad-Tags wie
/// `external/cwe/cwe-798`) und gibt kanonisch `CWE-<digits>` zurueck.
fn extract_cwe(text: &str) -> Option<String> {
    let up = text.to_ascii_uppercase();
    let b = up.as_bytes();
    let mut i = 0;
    while i + 3 <= b.len() {
        if b[i..i + 3] == *b"CWE" {
            let mut j = i + 3;
            while j < b.len() && matches!(b[j], b'-' | b' ' | b'/' | b'.' | b':' | b'_') {
                j += 1;
            }
            let start = j;
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
            if start < j {
                return Some(format!("CWE-{}", &up[start..j]));
            }
        }
        i += 1;
    }
    None
}

/// `properties.cwe` (String, Zahl oder Array davon) -> kanonische CWE.
fn value_cwe(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::String(s) => extract_cwe(s),
        serde_json::Value::Number(n) => Some(format!("CWE-{n}")),
        serde_json::Value::Array(a) => a.iter().find_map(value_cwe),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimal_import_is_e1() {
        let json = r#"{"version":"2.1.0","runs":[{"results":[
          {"ruleId":"no-eval","message":{"text":"avoid eval"},"level":"error",
           "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.js"},"region":{"startLine":3}}}]}
        ]}]}"#;
        let f = import_sarif(json).unwrap();
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].evidence, EvidenceLevel::E1);
        assert_eq!(f[0].path, "a.js");
        assert!(!f[0].unlocated);
    }

    #[test]
    fn missing_location_is_unlocated() {
        // Leeres locations-Array -> unlocated (kein Health-Score).
        let json = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep"}},
          "results":[{"ruleId":"r","message":{"text":"x"},"locations":[]}]}]}"#;
        let f = import_sarif(json).unwrap();
        assert_eq!(f.len(), 1);
        assert!(f[0].unlocated);
        assert_eq!(f[0].path, "");
        assert_eq!(f[0].start_line, 0);
    }

    #[test]
    fn empty_uri_is_unlocated() {
        // physicalLocation ohne uri -> ebenfalls unverwertbar.
        let json = r#"{"version":"2.1.0","runs":[{"results":[
          {"ruleId":"r","message":{"text":"x"},
           "locations":[{"physicalLocation":{"artifactLocation":{"uri":"  "},"region":{}}}]}
        ]}]}"#;
        let f = import_sarif(json).unwrap();
        assert!(f[0].unlocated);
    }

    #[test]
    fn provenance_codeql_and_semgrep() {
        let semgrep = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"Semgrep OSS"}},
          "results":[{"ruleId":"r","message":{"text":"x"},
           "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{}}}]}]}]}"#;
        let codeql = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL"}},
          "results":[{"ruleId":"js/hardcoded-credentials","message":{"text":"y"},
           "locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.js"},"region":{}}}]}]}]}"#;
        assert_eq!(import_sarif(semgrep).unwrap()[0].provenance, "semgrep");
        assert_eq!(import_sarif(codeql).unwrap()[0].provenance, "codeql");
    }

    #[test]
    fn cwe_from_codeql_tags_and_semgrep_props() {
        // CodeQL-Stil: external/cwe/cwe-798 in rule-Tags.
        let codeql = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"CodeQL",
          "rules":[{"id":"js/hardcoded-credentials","properties":{"tags":["security","external/cwe/cwe-798"]}}]}},
          "results":[{"ruleId":"js/hardcoded-credentials","message":{"text":"cred"},
           "locations":[{"physicalLocation":{"artifactLocation":{"uri":"b.js"},"region":{}}}]}]}]}"#;
        // Semgrep-Stil: properties.cwe am Rule-Eintrag.
        let semgrep = r#"{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"semgrep",
          "rules":[{"id":"py-md5","properties":{"cwe":"CWE-328"}}]}},
          "results":[{"ruleId":"py-md5","message":{"text":"md5"},
           "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.py"},"region":{}}}]}]}]}"#;
        assert_eq!(import_sarif(codeql).unwrap()[0].cwe, "CWE-798");
        assert_eq!(import_sarif(semgrep).unwrap()[0].cwe, "CWE-328");
        // Fallback: CWE in ruleId, sonst CWE-000.
        let plain = r#"{"version":"2.1.0","runs":[{"results":[
          {"ruleId":"no-eval","message":{"text":"x"},
           "locations":[{"physicalLocation":{"artifactLocation":{"uri":"a.js"},"region":{}}}]}
        ]}]}"#;
        assert_eq!(import_sarif(plain).unwrap()[0].cwe, "CWE-000");
    }
}
