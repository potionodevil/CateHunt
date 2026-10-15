// Testprojekt-Sample (nur fuer Offline-Tests): tiefe Verschachtelung,
// damit Stufe 1 flaggt (nesting 4 > 3) und complexity_hint greift.
// CWE-79 ohne Architektur-Keyword: reiner Komplexitaets-Fall.
fn handle_input(input: &str) -> &str {
    if !input.is_empty() {
        while input.len() > 0 {
            if input.starts_with('a') {
                return input;
            }
            break;
        }
    }
    "leer"
}
