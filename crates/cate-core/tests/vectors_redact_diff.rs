// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! P1 Vektor-Suite (deterministischer cargo-fuzz-Ersatz).
//!
//! `cargo-fuzz` ist offline nicht verfuegbar; diese Suite deckt die
//! Fuzz-Ziele aus docs/TESTING.md §1.2 deterministisch ab.
//!
//! - **redact**: Token-Muster, Idempotenz, No-Leak-Nachscan
//! - **diff-parser** (`parse_git_diff_name_status`): wilde Diffs
//!   (CRLF-Mix, Riesenhunks, Binaermarker, overlong Pfade)
//!
//! Invarianten: kein Secret im Output, kein Panic, typisierte Ergebnisse.
//! PRNG unten: xorshift64 mit fixem Seed (reproduzierbar, kein `rand`-Dep).
use cate_core::redact::{has_secret, redact_text, REDACTED};
use cate_core::scope::parse_git_diff_name_status;

/// Feste Token-Vektoren: (Name, eingebetteter Secret-Text).
fn secret_vectors() -> Vec<(&'static str, String)> {
    vec![
        ("sk", "key = \"sk-abcdefgh12345678\" done".into()),
        ("sk_long", format!("x sk-{} y", "A".repeat(64))),
        ("ghp", "token ghp_abcdefgh1234567890 rest".into()),
        ("akia", "aws_key=AKIAIOSFODNN7EXAMPLE end".into()),
        (
            "pem",
            "h\n-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK3x\n-----END RSA PRIVATE KEY-----\nf".into(),
        ),
        ("pem_no_end", "h\n-----BEGIN EC PRIVATE KEY-----\nMIIBOgIBAA".into()),
        ("password", "db_password = 'p@ss w0rt', user=x".into()),
        ("password_quoted", "PASSWORD=\"s3cret!\";".into()),
        (
            "mixed",
            "sk-abcdefgh12345678 und ghp_abcdefgh1234567890 \
             plus AKIAIOSFODNN7EXAMPLE und password=hunter2".into(),
        ),
    ]
}

#[test]
fn token_vectors_no_leak_in_output() {
    for (name, secret) in secret_vectors() {
        let code = format!("fn f() {{\n  // config: {secret}\n  let x = 1;\n}}");
        let out = redact_text(&code);
        assert!(!has_secret(&out), "Nachscan schlaegt an ({name}): {out}");
        assert!(
            out.contains(REDACTED) || out.contains("PRIVATE KEY]"),
            "kein Redaktions-Marker ({name}): {out}"
        );
        assert!(out.contains("fn f()"), "Umgebung verloren ({name})");
    }
}

#[test]
fn redact_idempotent_on_all_vectors() {
    let mut cases: Vec<String> = secret_vectors().into_iter().map(|(_, s)| s).collect();
    cases.extend([
        String::new(),
        "harmloser text ohne secrets".into(),
        "sk- kurz, ghp_ kurz".into(),
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----".into(),
        "password ohne wert".into(),
        "AKIAIOSHORT ref".into(),
        "emoji 🦀 sk-abcdefgh12345678 ende".into(),
        "null\x00byte sk-abcdefgh12345678".into(),
    ]);
    for c in &cases {
        let once = redact_text(c);
        let twice = redact_text(&once);
        assert_eq!(once, twice, "nicht idempotent: {c:?} -> {once:?}");
    }
}

#[test]
fn token_boundary_7_vs_8_chars() {
    // 7 Zeichen nach Prefix: untouched; 8 Zeichen: redigiert.
    assert_eq!(redact_text("x sk-abcdefg y"), "x sk-abcdefg y");
    assert!(redact_text("x sk-abcdefgh y").contains("sk-[REDACTED]"));
    assert_eq!(redact_text("x ghp_abcdefg y"), "x ghp_abcdefg y");
    assert!(redact_text("x ghp_abcdefgh y").contains("ghp_[REDACTED]"));
}

#[test]
fn diff_parser_wild_inputs_never_panics() {
    let overlong = format!("M\t{}\n", "a".repeat(300));
    let huge_line = format!("M\t{}\n", "b".repeat(100_000));
    let cases: Vec<String> = vec![
        String::new(),
        "\n\n\n".into(),
        "M\ta.rs\r\nA\tb.rs\r\n".into(),         // CRLF-Mix
        "M\ta.rs\n\r\nA\t\n".into(),             // leere Pfade
        "???\nM\tok.rs\n".into(),                // garbage-Status
        "R100\tsrc/alt.rs\tsrc/neu.rs\n".into(), // rename
        "R100\tnur-alt.rs\n".into(),             // rename ohne Neupfad
        "C75\ta.rs\tb.rs\n".into(),              // copy
        "M\ta b mit leerzeichen.rs\n".into(),    // spaces
        "M\tünïcödé/ß.rs\n".into(),              // unicode
        "M\tnull\x00byte.rs\n".into(),           // binaermarker
        "M\tp\ta\tb\trest\n".into(),             // zu viele tabs
        "\t\n".into(),                           // nur tab
        "M".into(),                              // status ohne tab
        overlong,
        huge_line,
        "X\tunknown-status-file.rs\n".into(),
        "B\tbroken.rs\n".into(),
        "m\tklein.rs\n".into(), // kleinbuchstabe: unbekannt -> skip
        "M\tsrc/a.rs\nM\tsrc/a.rs\n".into(), // duplikat
    ];
    for (i, input) in cases.iter().enumerate() {
        let files = parse_git_diff_name_status(input);
        for f in &files {
            assert!(
                matches!(
                    f.status,
                    'A' | 'M' | 'D' | 'R' | 'C' | 'T' | 'U' | 'X' | 'B'
                ),
                "Fall {i}: untypisierter Status {:?}",
                f.status
            );
            assert!(!f.path.is_empty(), "Fall {i}: leerer Pfad");
            assert!(!f.path.contains('\0'), "Fall {i}: NUL im Pfad");
        }
    }
    // Erwartete Positivfaelle separat:
    assert_eq!(parse_git_diff_name_status("M\ta.rs\n").len(), 1);
    assert_eq!(
        parse_git_diff_name_status("R100\ta.rs\tb.rs\n")[0].path,
        "b.rs"
    );
    assert!(parse_git_diff_name_status("???\n").is_empty());
    assert!(parse_git_diff_name_status("m\tklein.rs\n").is_empty());
}

/// Deterministischer PRNG (xorshift64, fixer Seed): 5000 synthetisierte
/// Diff-Zeilen duerfen nie panicen und liefern nur typisierte Ergebnisse.
fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

#[test]
fn diff_parser_deterministic_pseudo_fuzz() {
    const ALPHABET: &[u8] = b"AMDRCTUXB../\\\t\r\n\0?;:{}aZ09_-.\xc3\xa9";
    let mut state: u64 = 0x1234_5678_9abc_def1;
    let mut buf = String::new();
    for iter in 0..5000 {
        buf.clear();
        let n_lines = (xorshift(&mut state) % 4) as usize;
        for _ in 0..=n_lines {
            let len = (xorshift(&mut state) % 48) as usize;
            for _ in 0..len {
                let b = ALPHABET[(xorshift(&mut state) % ALPHABET.len() as u64) as usize];
                buf.push(b as char);
            }
            buf.push('\n');
        }
        let files = parse_git_diff_name_status(&buf);
        for f in &files {
            assert!(
                matches!(
                    f.status,
                    'A' | 'M' | 'D' | 'R' | 'C' | 'T' | 'U' | 'X' | 'B'
                ),
                "iter {iter}: untypisiert {:?}",
                f.status
            );
            assert!(!f.path.is_empty(), "iter {iter}: leerer Pfad");
        }
    }
}
