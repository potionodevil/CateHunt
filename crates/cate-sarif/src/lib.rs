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
}

#[derive(Debug, Deserialize)]
struct SarifLog {
    runs: Vec<SarifRun>,
}

#[derive(Debug, Deserialize)]
struct SarifRun {
    #[serde(default)]
    results: Vec<SarifResult>,
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
pub fn import_sarif(json: &str) -> Result<Vec<SarifFinding>, String> {
    let log: SarifLog = serde_json::from_str(json).map_err(|e| format!("sarif parse: {e}"))?;
    let mut out = Vec::new();
    for run in &log.runs {
        for r in &run.results {
            let (path, line) = r
                .locations
                .first()
                .map(|l| {
                    (
                        l.physical_location.artifact_location.uri.clone(),
                        l.physical_location.region.start_line,
                    )
                })
                .unwrap_or((String::new(), 0));
            out.push(SarifFinding {
                rule_id: if r.rule_id.is_empty() {
                    "unknown".to_string()
                } else {
                    r.rule_id.clone()
                },
                message: r.message.text.clone(),
                path,
                start_line: line,
                level: r.level.clone().unwrap_or_else(|| "warning".to_string()),
                evidence: EvidenceLevel::E1,
            });
        }
    }
    Ok(out)
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
    }
}
