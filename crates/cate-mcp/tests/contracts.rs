// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! Contract-Tests fuer cate-mcp (je Tool + Fehlerfaelle + JSON-RPC-Smoke).
use cate_mcp::{handle_request, ProposalStore};
use serde_json::{json, Value};

fn req(method: &str, params: Value) -> Value {
    json!({"jsonrpc":"2.0","id":1,"method":method,"params":params})
}

fn err_code(resp: &Value) -> String {
    resp["error"]["data"]["code"]
        .as_str()
        .unwrap_or("")
        .to_string()
}

#[test]
fn audit_diff_missing_base_is_invalid_params() {
    let r = handle_request(
        &req("audit_diff", json!({})),
        std::path::Path::new("."),
        &mut ProposalStore::new(),
    );
    assert_eq!(err_code(&r), "INVALID_PARAMS");
}

#[test]
fn audit_diff_bad_rev_is_not_found() {
    let r = handle_request(
        &req("audit_diff", json!({"base":"rev-die-es-nie-gibt-xyz"})),
        std::path::Path::new("."),
        &mut ProposalStore::new(),
    );
    assert_eq!(err_code(&r), "NOT_FOUND");
}

#[test]
fn audit_diff_path_escape_is_invalid_path() {
    let r = handle_request(
        &req(
            "audit_diff",
            json!({"base":"HEAD","paths":["../etc/passwd"]}),
        ),
        std::path::Path::new("."),
        &mut ProposalStore::new(),
    );
    assert_eq!(err_code(&r), "INVALID_PATH");
}

#[test]
fn get_graph_missing_path_is_invalid_params() {
    let r = handle_request(
        &req("get_graph", json!({})),
        std::path::Path::new("."),
        &mut ProposalStore::new(),
    );
    assert_eq!(err_code(&r), "INVALID_PARAMS");
}

#[test]
fn get_graph_escape_is_invalid_path() {
    let r = handle_request(
        &req("get_graph", json!({"path":"../../etc"})),
        std::path::Path::new("."),
        &mut ProposalStore::new(),
    );
    assert_eq!(err_code(&r), "INVALID_PATH");
}

#[test]
fn get_graph_nonexistent_is_invalid_path() {
    let r = handle_request(
        &req("get_graph", json!({"path":"gibt-es-nicht-xyz"})),
        std::path::Path::new("."),
        &mut ProposalStore::new(),
    );
    assert_eq!(err_code(&r), "INVALID_PATH");
}

#[test]
fn explain_nesting_missing_file_is_invalid_params() {
    let r = handle_request(
        &req("explain_nesting", json!({})),
        std::path::Path::new("."),
        &mut ProposalStore::new(),
    );
    assert_eq!(err_code(&r), "INVALID_PARAMS");
}

#[test]
fn explain_nesting_escape_is_invalid_path() {
    let r = handle_request(
        &req("explain_nesting", json!({"file":"../ausbruch.rs"})),
        std::path::Path::new("."),
        &mut ProposalStore::new(),
    );
    assert_eq!(err_code(&r), "INVALID_PATH");
}

#[test]
fn explain_nesting_missing_file_on_disk_is_invalid_path() {
    let r = handle_request(
        &req("explain_nesting", json!({"file":"gibt-es-nicht.rs"})),
        std::path::Path::new("."),
        &mut ProposalStore::new(),
    );
    assert_eq!(err_code(&r), "INVALID_PATH");
}

#[test]
fn apply_proposal_without_approval_is_approval_required() {
    let mut s = ProposalStore::new();
    s.register_demo("nest-2026-001");
    let r = handle_request(
        &req("apply_proposal", json!({"proposal_id":"nest-2026-001"})),
        std::path::Path::new("."),
        &mut s,
    );
    assert_eq!(err_code(&r), "APPROVAL_REQUIRED");
    assert!(
        !s.audit_log().is_empty(),
        "Ablehnung muss audit-geloggt sein"
    );
}

#[test]
fn apply_proposal_auto_apply_without_approver_is_approval_required() {
    let mut s = ProposalStore::new();
    s.register_demo("p-auto");
    let r = handle_request(
        &req(
            "apply_proposal",
            json!({"proposal_id":"p-auto","auto_apply":true}),
        ),
        std::path::Path::new("."),
        &mut s,
    );
    assert_eq!(err_code(&r), "APPROVAL_REQUIRED");
}

#[test]
fn apply_proposal_unknown_id_is_not_found() {
    let r = handle_request(
        &req(
            "apply_proposal",
            json!({"proposal_id":"unbekannt","approved_by":"r.siepmann"}),
        ),
        std::path::Path::new("."),
        &mut ProposalStore::new(),
    );
    assert_eq!(err_code(&r), "NOT_FOUND");
}

#[test]
fn apply_proposal_approved_applies_and_logs() {
    let mut s = ProposalStore::new();
    s.register_demo("nest-2026-001");
    let r = handle_request(
        &req(
            "apply_proposal",
            json!({"proposal_id":"nest-2026-001","approved_by":"r.siepmann"}),
        ),
        std::path::Path::new("."),
        &mut s,
    );
    assert!(r.get("error").is_none(), "darf kein Fehler sein: {r}");
    assert_eq!(r["result"]["applied"], true);
    assert!(r["result"]["audit_log_id"].as_str().is_some());
}

fn repo_root() -> std::path::PathBuf {
    let m = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    m.parent()
        .and_then(|p| p.parent())
        .unwrap_or(m)
        .to_path_buf()
}

#[test]
fn audit_diff_head_succeeds_with_schema_fields() {
    let root = repo_root();
    let r = handle_request(
        &req("audit_diff", json!({"base":"HEAD"})),
        &root,
        &mut ProposalStore::new(),
    );
    assert!(r.get("error").is_none(), "unerwarteter Fehler: {r}");
    for f in ["base", "head", "changed_files", "inventory", "issues"] {
        assert!(r["result"].get(f).is_some(), "Feld {f} fehlt: {r}");
    }
}

#[test]
fn get_graph_core_src_succeeds() {
    let root = repo_root();
    let r = handle_request(
        &req("get_graph", json!({"path":"crates/cate-core/src"})),
        &root,
        &mut ProposalStore::new(),
    );
    assert!(r.get("error").is_none(), "unerwarteter Fehler: {r}");
    assert!(!r["result"]["nodes"].as_array().unwrap().is_empty());
    assert!(r["result"]["health"]["score_0_100"].as_u64().unwrap() <= 100);
}

#[test]
fn explain_nesting_lib_rs_succeeds() {
    let root = repo_root();
    let r = handle_request(
        &req(
            "explain_nesting",
            json!({"file":"crates/cate-core/src/lib.rs"}),
        ),
        &root,
        &mut ProposalStore::new(),
    );
    assert!(r.get("error").is_none(), "unerwarteter Fehler: {r}");
    assert!(r["result"]["patch_suggestion"].as_str().is_some());
    assert!(r["result"]["rationale"].as_str().is_some());
}

#[test]
fn unknown_method_is_method_not_found() {
    let r = handle_request(
        &req("gibts_nicht", json!({})),
        std::path::Path::new("."),
        &mut ProposalStore::new(),
    );
    assert!(r["error"]["message"]
        .as_str()
        .unwrap()
        .contains("Method not found"));
}

#[test]
fn ping_echoes_params() {
    let r = handle_request(
        &req("ping", json!({"hello":"welt"})),
        std::path::Path::new("."),
        &mut ProposalStore::new(),
    );
    assert_eq!(r["result"]["echo"]["hello"], "welt");
}
