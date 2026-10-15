// Copyright (c) 2026 R.S. - Geistiges Eigentum von R.S. Kopieren, Vervielfaeltigung
// oder Veraenderung ohne ausdrueckliche Genehmigung nicht erlaubt.
//! cate-mcp Binary: JSON-RPC ueber stdio (je Zeile ein Request, kein Netz).
use cate_mcp::{handle_request, ProposalStore};
use std::io::BufRead;

fn main() {
    let root = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
    let mut store = ProposalStore::new();
    // Kein Demo-Seed im Prod-Binary (nur Tests nutzen register_demo);
    // unbekannte proposal_id -> NOT_FOUND, keine Genehmigung -> APPROVAL_REQUIRED.
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let req: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(e) => {
                println!(
                    "{}",
                    serde_json::json!({"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":format!("Parse error: {e}"),"data":{"code":"INVALID_PARAMS","message":format!("Parse error: {e}")}}})
                );
                continue;
            }
        };
        let resp = handle_request(&req, &root, &mut store);
        println!("{}", serde_json::to_string(&resp).unwrap_or_default());
    }
}
