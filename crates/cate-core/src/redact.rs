// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! Secrets-Redaction (Paket B, REVIEW M-8).
//!
//! Entfernt Secret-Material aus Strings (Logs, Reports, Prompts),
//! bevor diese serialisiert oder an ein Modell uebergeben werden.
//! Keine Abhaengigkeit von `regex` — bewusst einfache, ueberapproximierende
//! Scanner (lieber einmal zu viel redigieren als ein Secret durchlassen).

/// Platzhalter fuer redigierten Inhalt.
pub const REDACTED: &str = "[REDACTED]";

/// Prueft, ob `s` (vermutlich) Secret-Material enthaelt.
/// Ueberapproximierend; fuer Negativ-Assertions in Tests
/// ("Report enthaelt keine Roh-Secrets").
pub fn has_secret(s: &str) -> bool {
    redact_text(s) != s
}

/// Redigiert Secrets in freiem Text. Folgende Muster werden ersetzt:
/// - `sk-<alnum...>` (OpenAI-Style API-Keys)
/// - `ghp_<alnum...>` (GitHub PATs)
/// - `AKIA<16 x alnum>` (AWS Access Key IDs)
/// - `-----BEGIN ... PRIVATE KEY----- ... -----END ...-----` (PEM-Bloecke)
/// - `password\s*=\s*<wert>` (case-insensitiv, Wert bis Whitespace/Quote/Semikolon)
pub fn redact_text(input: &str) -> String {
    let mut out = input.to_string();
    out = redact_pem_blocks(&out);
    out = redact_prefixed_token(&out, "sk-", "sk-");
    out = redact_prefixed_token(&out, "ghp_", "ghp_");
    out = redact_akia(&out);
    out = redact_password_assign(&out);
    out
}

/// Redigiert rekursiv alle Strings in einem JSON-Wert (in place).
pub fn redact_value(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::String(s) => {
            let r = redact_text(s);
            *s = r;
        }
        serde_json::Value::Array(a) => {
            for x in a {
                redact_value(x);
            }
        }
        serde_json::Value::Object(m) => {
            for (_, x) in m.iter_mut() {
                redact_value(x);
            }
        }
        _ => {}
    }
}

fn is_token_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// Ersetzt `prefix` + anschliessenden Token-Run durch `label` + REDACTED.
/// Der Token-Run muss mind. 8 Zeichen lang sein (vermeidet False Positives
/// wie `sk-` in Prosa); kuerzere Vorkommen bleiben unveraendert.
fn redact_prefixed_token(s: &str, prefix: &str, label: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(idx) = rest.find(prefix) {
        out.push_str(&rest[..idx]);
        let after = &rest[idx + prefix.len()..];
        let run_len: usize = after.chars().take_while(|c| is_token_char(*c)).count();
        if run_len >= 8 {
            let byte_len: usize = after
                .chars()
                .take_while(|c| is_token_char(*c))
                .map(|c| c.len_utf8())
                .sum();
            out.push_str(label);
            out.push_str(REDACTED);
            rest = &after[byte_len..];
        } else {
            out.push_str(prefix);
            rest = after;
        }
    }
    out.push_str(rest);
    out
}

/// `AKIA` + genau 16 alphanumerische Zeichen (AWS Access Key ID, 20 Stellen).
/// Kuerzere/laengere Folgen werden nicht angeruehrt.
fn redact_akia(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(idx) = rest.find("AKIA") {
        out.push_str(&rest[..idx]);
        let after = &rest[idx + 4..];
        let run: String = after
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric())
            .collect();
        if run.len() == 16 {
            // Naechstes Zeichen darf kein Token-Zeichen sein (exakte 20 Stellen).
            let next_is_token = after.chars().nth(16).map(is_token_char).unwrap_or(false);
            if !next_is_token {
                out.push_str(REDACTED);
                rest = &after[run.len()..];
                continue;
            }
        }
        out.push_str("AKIA");
        rest = after;
    }
    out.push_str(rest);
    out
}

/// PEM-Private-Key-Bloecke: von `-----BEGIN ...PRIVATE KEY-----`
/// bis zum naechsten `-----END ...-----` alles ersetzen.
fn redact_pem_blocks(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(b) = rest.find("-----BEGIN") {
        if let Some(key_pos) = rest[b..].find("PRIVATE KEY-----") {
            let body_start = b + key_pos + "PRIVATE KEY-----".len();
            if let Some(e) = rest[body_start..].find("-----END") {
                if let Some(dash_end) = rest[body_start + e..].find("-----") {
                    // Ende der END-Zeile bestimmen (zweites "-----" + Rest der Zeile lassen).
                    let end_marker_end = body_start + e + dash_end + "-----".len();
                    out.push_str(&rest[..b]);
                    out.push_str("[REDACTED PRIVATE KEY]");
                    rest = &rest[end_marker_end..];
                    continue;
                }
            }
            // Kein END gefunden: ab BEGIN bis Stringende redigieren.
            out.push_str(&rest[..b]);
            out.push_str("[REDACTED PRIVATE KEY]");
            return out;
        }
        // "-----BEGIN" ohne PRIVATE KEY (z.B. CERTIFICATE): unveraendert lassen.
        out.push_str(&rest[..b + "-----BEGIN".len()]);
        rest = &rest[b + "-----BEGIN".len()..];
    }
    out.push_str(rest);
    out
}

/// `password = <wert>` (case-insensitiv, optionale Quotes, Wert endet an
/// Whitespace, Quote, Komma oder Semikolon) -> `password=[REDACTED]`.
fn redact_password_assign(s: &str) -> String {
    let lower = s.to_lowercase();
    let mut out = String::with_capacity(s.len());
    let mut i = 0usize;
    let bytes = s.as_bytes();
    while let Some(rel) = lower[i..].find("password") {
        let abs = i + rel;
        let mut j = abs + "password".len();
        // optionale Whitespaces
        while j < s.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
            j += 1;
        }
        if j < s.len() && bytes[j] == b'=' {
            j += 1;
            while j < s.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
            // optionales Anfuehrungszeichen merken
            let mut quote: Option<u8> = None;
            if j < s.len() && (bytes[j] == b'"' || bytes[j] == b'\'') {
                quote = Some(bytes[j]);
                j += 1;
            }
            let val_start = j;
            while j < s.len() {
                let c = bytes[j];
                if let Some(q) = quote {
                    if c == q {
                        break;
                    }
                } else if c == b' '
                    || c == b'\t'
                    || c == b'\n'
                    || c == b'\r'
                    || c == b','
                    || c == b';'
                    || c == b'"'
                    || c == b'\''
                {
                    break;
                }
                j += 1;
            }
            if j > val_start {
                out.push_str(&s[i..abs]);
                out.push_str("password=");
                out.push_str(REDACTED);
                // schliessendes Quote uebernehmen, falls vorhanden
                if let Some(q) = quote {
                    if j < s.len() && bytes[j] == q {
                        out.push(q as char);
                        j += 1;
                    }
                }
                i = j;
                continue;
            }
        }
        out.push_str(&s[i..abs + "password".len()]);
        i = abs + "password".len();
    }
    out.push_str(&s[i..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_sk_key() {
        let s = "api_key = \"sk-abcDEF1234567890XYZ\"";
        let r = redact_text(s);
        assert!(!r.contains("sk-abcDEF"), "leak: {r}");
        assert!(r.contains("sk-[REDACTED]"), "marker fehlt: {r}");
    }

    #[test]
    fn redacts_ghp_token() {
        let s = "token ghp_abcdefghij1234567890 rest";
        let r = redact_text(s);
        assert!(!r.contains("ghp_abcdef"), "leak: {r}");
        assert!(r.contains("ghp_[REDACTED]"), "marker fehlt: {r}");
    }

    #[test]
    fn redacts_akia_key() {
        let s = "aws_key=AKIAIOSFODNN7EXAMPLE";
        let r = redact_text(s);
        assert!(!r.contains("AKIAIOSF"), "leak: {r}");
        assert!(r.contains(REDACTED), "marker fehlt: {r}");
    }

    #[test]
    fn akia_wrong_length_untouched() {
        let s = "AKIAIOSHORT ref AKIAIOSFODNN7EXAMPLETOOLONGVALUE";
        let r = redact_text(s);
        assert!(r.contains("AKIAIOSHORT"), "falsch redigiert: {r}");
    }

    #[test]
    fn redacts_private_key_block() {
        let s = "header\n-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----\nfooter";
        let r = redact_text(s);
        assert!(!r.contains("MIIBOg"), "leak: {r}");
        assert!(!r.contains("BEGIN RSA"), "leak: {r}");
        assert!(r.contains("footer"), "umgebung verloren: {r}");
    }

    #[test]
    fn certificate_block_untouched() {
        let s = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----";
        let r = redact_text(s);
        assert_eq!(r, s, "cert darf nicht redigiert werden");
    }

    #[test]
    fn redacts_password_assign() {
        for s in [
            "password=hunter2 rest",
            "password = hunter2",
            "PASSWORD=\"s3cret!\";",
            "db_password = 'p@ss w0rt', user=x",
        ] {
            let r = redact_text(s);
            assert!(!r.to_lowercase().contains("hunter2"), "leak: {r}");
            assert!(!r.contains("s3cret"), "leak: {r}");
            assert!(!r.contains("p@ss"), "leak: {r}");
            assert!(r.to_lowercase().contains("password="), "label fehlt: {r}");
        }
    }

    #[test]
    fn plain_text_untouched() {
        let s = "fn main() { println!(\"hello\"); } // no secrets here";
        assert_eq!(redact_text(s), s);
    }

    #[test]
    fn short_prefix_untouched() {
        // "sk-" in Prosa ohne Token-Run: kein False Positive.
        // ("ghp_-Tokens": Run nach Prefix nur 7 Zeichen -> untouched.)
        let s = "die sk- enden hier, ghp_-Tokens sind kurz";
        assert_eq!(redact_text(s), s);
    }

    #[test]
    fn has_secret_flags_and_clears() {
        assert!(has_secret("x sk-abcDEF1234567890 y"));
        assert!(!has_secret("harmloser text"));
        let r = redact_text("x sk-abcDEF1234567890 y");
        assert!(!has_secret(&r), "nicht idempotent/stabil: {r}");
    }

    #[test]
    fn redact_value_recurses_json() {
        let mut v = serde_json::json!({
            "message": "leak sk-abcDEF1234567890 done",
            "nested": {"k": "password=hunter2"},
            "n": 42,
            "arr": ["ghp_abcdefghij1234567890"]
        });
        redact_value(&mut v);
        let s = serde_json::to_string(&v).unwrap();
        assert!(!s.contains("sk-abcDEF"), "leak: {s}");
        assert!(!s.contains("hunter2"), "leak: {s}");
        assert!(!s.contains("ghp_abcdef"), "leak: {s}");
        assert_eq!(v["n"], 42);
    }
}
